#!/bin/bash
# openrouter.sh - OpenRouter API interface for AI-powered README parsing
# Requires: curl, jq

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    if [[ -n "${OPENROUTER_SH_LOADED:-}" ]]; then
        return 0
    fi
    declare -gr OPENROUTER_SH_LOADED=1
fi

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# OpenRouter API configuration
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
OPENROUTER_API_URL="${OPENROUTER_API_URL:-https://openrouter.ai/api/v1/chat/completions}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openrouter/free}"

# Configure after config.conf is loaded. Keep compatibility names for existing modules.
configure_ai() {
    case "${AI_PROVIDER:-openrouter}" in
        openrouter) OPENROUTER_API_URL="https://openrouter.ai/api/v1/chat/completions" ;;
        nvidia)
            OPENROUTER_API_URL="https://integrate.api.nvidia.com/v1/chat/completions"
            OPENROUTER_API_KEY="${NVIDIA_API_KEY:-}"
            OPENROUTER_MODEL="${NVIDIA_MODEL:-z-ai/glm-5.3-flash}"
            ;;
        *) log_error "AI_PROVIDER must be openrouter or nvidia"; return 1 ;;
    esac
    [[ "${AI_TIMEOUT_SECONDS:-180}" =~ ^[1-9][0-9]*$ ]] || { log_error "Invalid AI_TIMEOUT_SECONDS"; return 1; }
}

# System prompt for README extraction (adapted from PowerShell version)
# Use a heredoc to populate SYSTEM_PROMPT. read -d '' returns 1 at EOF when
# no NUL delimiter is encountered, so append `|| true` to avoid set -e exiting
# the script before initialization completes.
read -r -d '' SYSTEM_PROMPT <<'EOF' || true
You are a specialized assistant that extracts structured information from CyberPatriot competition README files.

Your task is to parse the README content and extract:
1. Every authorized user and their account type ("admin" or "standard"). Administrators are always authorized users, but not every authorized user is an administrator.
2. Recently hired/new users who need accounts created (recognize wording like "new department members" or "newly added users" as recent hires).
3. Terminated/unauthorized users whose accounts should be removed (recognize wording such as "terminated", "former", "to delete").
4. Critical services that must remain running.
5. Group memberships for each authorized user (include any groups mentioned for them).
6. Groups that need to be created along with the members to place in those groups (these may describe new departments such as "Create a group called \"spider\" and add may, peni, stan, miguel"—treat this as an example, not something to hardcode).
7. System users explicitly mentioned as needing restricted login.

Return ONLY valid JSON in this exact format:
{
  "all_users": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1", "group2"]}
  ],
  "recent_hires": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1"]}
  ],
  "terminated_users": ["username1", "username2"],
  "critical_services": ["ssh", "apache2"],
  "groups_to_create": [
    {"name": "groupname", "members": ["user1", "user2"]}
  ],
  "system_users_to_restrict": ["mysql"]
}

Guidelines:
- Extract ALL authorized users, and always include an "account_type" and any listed "groups" for each one.
- Identify users described as new, recently hired, to be created, or part of a newly formed department as recent hires.
- Identify users marked as terminated, removed, unauthorized, or former as terminated_users.
- Service names should be actual service names (e.g., "ssh", "apache2", "mysql").
- Account types: "admin" for administrators, "standard" for regular users.
- Extract any groups mentioned that should be created and capture all members listed for those groups (do not invent members; use only what appears in the README).
- Extract group memberships for all users, including admins and standard users.
- Capture system users to restrict ONLY when explicitly mentioned in the README.
- If information is not present, use empty arrays [].
- Return ONLY the JSON object, no additional text or explanation.
EOF

# Check if API key is configured
check_openrouter_config() {
    if [[ -z "$OPENROUTER_API_KEY" ]]; then
        log_error "${AI_PROVIDER:-openrouter} API key not configured"
        log_info "Set the selected provider's API key in config.local.conf"
        return 1
    fi
    return 0
}

# ---
# --- THIS IS THE FIXED FUNCTION ---
# ---
# Remove HTML tags from content (re-written with perl for multi-line support)
remove_html_tags() {
    local content="$1"

    # Use Perl for multi-line regex replacements
    # -0777 slurps the whole file
    # -p prints the result
    # 's|...|...|gis' -> g=global, i=case-insensitive, s=dot matches newline

    # Remove head, script, and style tags with their content (non-greedy)
    content=$(echo "$content" | perl -0777 -p -e 's|<head[^>]*>.*?</head>||gis')
    content=$(echo "$content" | perl -0777 -p -e 's|<script[^>]*>.*?</script>||gis')
    content=$(echo "$content" | perl -0777 -p -e 's|<style[^>]*>.*?</style>||gis')

    # Remove all remaining HTML tags
    content=$(echo "$content" | perl -0777 -p -e 's|<[^>]+>||g')

    # Collapse multiple whitespace to single space
    content=$(echo "$content" | tr -s '[:space:]' ' ')

    # Trim leading/trailing whitespace
    content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

    echo "$content"
}
# --- END OF FIXED FUNCTION ---

# Call OpenRouter API with README content
invoke_readme_extraction() {
    local plain_text="$1"
    local url="${2:-unknown}"

    if ! check_openrouter_config; then
        return 1
    fi

    log_debug "Calling OpenRouter API for README extraction..."
    log_debug "Using model: $OPENROUTER_MODEL"

    # Construct JSON payload
    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$SYSTEM_PROMPT" \
        --arg content "$plain_text" \
        '{
            "model": $model,
            "messages": [
                {
                    "role": "system",
                    "content": $system
                },
                {
                    "role": "user",
                    "content": $content
                }
            ],
            "temperature": 0.1,
            "max_tokens": 4000
        }')

    # Extraction needs final JSON rather than spending the whole budget on reasoning.
    if [[ "${AI_PROVIDER:-openrouter}" == nvidia && "$OPENROUTER_MODEL" == nvidia/nemotron-3-* ]]; then
        payload=$(printf '%s' "$payload" | jq '. + {chat_template_kwargs: {enable_thinking: false}}')
    fi
    # Make API request
    local response attempt
    for attempt in $(seq 1 "${AI_HTTP_RETRIES:-6}"); do
        response=$(curl -sS --connect-timeout 15 --max-time "${AI_TIMEOUT_SECONDS:-180}" -X POST "$OPENROUTER_API_URL" \
            -H "Authorization: Bearer $OPENROUTER_API_KEY" \
            -H "Content-Type: application/json" \
            -H "HTTP-Referer: https://github.com/cyberpatriot-linux-auto" \
            -d "$payload") || response=""
        # Back off and retry on network failure, 429 rate limits, or transient 5xx.
        if [[ -n "$response" ]] && ! grep -qiE '"(code|status)": *(429|50[0-4])|rate.?limit|too many requests' <<<"$response"; then
            break
        fi
        log_warn "AI request throttled or failed (attempt $attempt/${AI_HTTP_RETRIES:-6}); retrying..."
        sleep $((attempt * 8))
    done
    if [[ -z "$response" ]]; then
        log_error "Failed to call OpenRouter API"
        return 1
    fi

    # Extract the content from response
    local content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "Failed to parse OpenRouter API response"
        log_error "$(echo "$response" | jq -r '.error.message // "No final text returned; model may have exhausted its token budget"' 2>/dev/null)"
        return 1
    fi

    echo "$content"
    return 0
}

# ---
# --- THIS IS THE SECOND FIXED FUNCTION (more robust) ---
# ---
# Extract JSON from model response (handles cases where model adds extra text)
extract_json_from_response() {
    local text="$1"

    # Try to parse as-is first
    if echo "$text" | jq -e '.' >/dev/null 2>&1; then
        echo "$text"
        return 0
    fi

    # Try to parse JSON that is wrapped in a fenced ```json code block
    local fenced_json=$(echo "$text" | sed -n '/```json/,/```/p' | sed '1d;$d')
    if [[ -n "$fenced_json" ]] && echo "$fenced_json" | jq -e '.' >/dev/null 2>&1; then
        echo "$fenced_json"
        return 0
    fi

    # Try to parse JSON from any fenced code block
    local fenced_block=$(echo "$text" | sed -n '/```/,/```/p' | sed '1d;$d')
    if [[ -n "$fenced_block" ]] && echo "$fenced_block" | jq -e '.' >/dev/null 2>&1; then
        echo "$fenced_block"
        return 0
    fi

    # Try to extract JSON object from text
    # Use (?s) to make . (dot) match newlines, in case the JSON is multi-line
    local extracted=$(echo "$text" | grep -oP '(?s)\{.*\}' | head -1)

    if [[ -n "$extracted" ]] && echo "$extracted" | jq -e '.' >/dev/null 2>&1; then
        echo "$extracted"
        return 0
    fi

    # Try to extract a JSON array if no object was found
    local extracted_array=$(echo "$text" | grep -oP '(?s)\[.*\]' | head -1)
    if [[ -n "$extracted_array" ]] && echo "$extracted_array" | jq -e '.' >/dev/null 2>&1; then
        echo "$extracted_array"
        return 0
    fi

    log_error "Could not extract valid JSON from model response"
    log_debug "Raw model response: $text" # Added for better debugging
    return 1
}
# --- END OF FIXED FUNCTION ---

# Test OpenRouter connection
test_openrouter() {
    if ! check_openrouter_config; then
        return 1
    fi

    log_info "Testing ${AI_PROVIDER:-openrouter} API connection..."

    local test_payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        '{
            "model": $model,
            "messages": [
                {
                    "role": "user",
                    "content": "Say hello"
                }
            ],
            "max_tokens": 2048
        }')

    local response
    response=$(curl -sS --connect-timeout 15 --max-time "${AI_TIMEOUT_SECONDS:-180}" -X POST "$OPENROUTER_API_URL" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$test_payload") || { log_error "Analysis request failed or timed out"; return 1; }

    if echo "$response" | jq -e '.choices[0].message' >/dev/null 2>&1; then
        log_success "${AI_PROVIDER:-openrouter} API connection successful (model: $OPENROUTER_MODEL)"
        if ! echo "$response" | jq -e '.choices[0].message.content | strings | select(length > 0)' >/dev/null 2>&1; then
            log_warn "Connection works, but this test returned no final text. Extraction may need a different model/token budget."
        fi
        return 0
    else
        log_error "${AI_PROVIDER:-openrouter} API connection failed"
        log_error "$(echo "$response" | jq -r '.error.message // "Invalid API response"' 2>/dev/null)"
        return 1
    fi
}

export -f check_openrouter_config remove_html_tags invoke_readme_extraction
export -f extract_json_from_response test_openrouter
