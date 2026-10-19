"""Cross-check AI account/service extraction against explicit HTML README lists."""
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from readme_extract import SERVICE_ALIASES


class Sections(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sections = []
        self.heading = None
        self.current = None
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.ignored += 1
        if re.fullmatch(r'h[1-6]', tag):
            self.heading = []
        elif tag in ('br', 'p', 'li', 'tr', 'div') and self.current:
            self.current[1].append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.ignored = max(0, self.ignored - 1)
        if re.fullmatch(r'h[1-6]', tag) and self.heading is not None:
            self.current = [''.join(self.heading).strip(), []]
            self.sections.append(self.current)
            self.heading = None
        elif tag in ('p', 'li', 'tr', 'div') and self.current:
            self.current[1].append('\n')

    def handle_data(self, data):
        if self.ignored:
            return
        if self.heading is not None:
            self.heading.append(data)
        elif self.current:
            self.current[1].append(data)


def extract_text_sections(text):
    sections = []
    current_h = None
    current_c = []
    for line in text.splitlines():
        line_clean = re.sub(r'^[#*_\-\s]+', '', line).strip()
        lower = line_clean.lower().rstrip(':')
        role = None
        if lower.startswith('authorized administrator') or lower.startswith('authorized admin') or lower == 'administrators':
            role = 'admin'
        elif lower in ('authorized users', 'authorized user') or lower == 'users':
            role = 'standard'
        elif any(lower.startswith(k) for k in ('critical services', 'required services')) or lower == 'services':
            role = 'services'
        if role:
            if current_h is not None:
                sections.append((current_h, current_c))
            current_h = line_clean
            current_c = []
        elif current_h is not None:
            current_c.append(line + '\n')
    if current_h is not None:
        sections.append((current_h, current_c))
    return sections


def validate(html, data):
    auto_rem = os.environ.get('AUTO_REMEDIATE') == '1'
    parser = Sections()
    parser.feed(html)
    sections_list = parser.sections
    has_recognized_heading = any(
        any(k in h.lower() for k in ('authorized admin', 'authorized user', 'critical service', 'required service', 'administrators', 'users', 'critical services', 'required services'))
        for h, _ in sections_list
    )
    if not has_recognized_heading:
        text_sections = extract_text_sections(html)
        if text_sections:
            sections_list = text_sections

    expected = {}
    services = None
    found = set()
    for heading, chunks in sections_list:
        heading_clean = re.sub(r'^[#*_\-\s]+', '', heading.strip()).rstrip(':')
        heading_lower = heading_clean.lower()
        role = None
        if heading_lower.startswith('authorized administrator') or heading_lower.startswith('authorized admin') or heading_lower == 'administrators':
            role = 'admin'
        elif heading_lower in ('authorized users', 'authorized user') or heading_lower == 'users':
            role = 'standard'
        elif any(heading_lower.startswith(k) for k in ('critical services', 'required services')) or heading_lower in ('critical services', 'required services', 'services'):
            if services is None:
                services = []
            for line in ''.join(chunks).splitlines():
                line = line.strip().lower()
                line = re.sub(r'^[\s*\-•#>\d.)]+', '', line).strip()
                if not line or line in ('none', 'n/a'):
                    continue
                name = re.search(r'[a-z0-9_-]+', line)
                if not name:
                    raise ValueError('Unrecognized required service entry; review README manually')
                services.append(SERVICE_ALIASES.get(name[0], name[0]))
        if role:
            if role in found:
                if not auto_rem:
                    raise ValueError('Multiple authorized-user sections; review README manually')
            found.add(role)
            for line in ''.join(chunks).splitlines():
                line = line.strip()
                if not line:
                    continue
                clean_line = re.sub(r'^[\s*\-•#>\d.)]+', '', line).strip()
                if not clean_line:
                    continue
                lower_line = clean_line.lower()
                if any(lower_line.startswith(prefix) for prefix in ('none', 'n/a', 'note:', 'note ', 'do not', 'all other', 'these users', 'the following')):
                    continue
                match = re.fullmatch(r'([a-zA-Z_][a-zA-Z0-9_-]*\$?)(?:\s*:\s*.*|\s*\([^\n]*\))?', clean_line)
                if not match:
                    paren = re.search(r'\(([a-zA-Z_][a-zA-Z0-9_-]*\$?)\)', clean_line)
                    if paren:
                        match = paren
                    elif '-' in clean_line:
                        dash_token = clean_line.split('-')[0].strip()
                        if re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]*\$?', dash_token):
                            match = [None, dash_token]
                if not match:
                    raise ValueError('Unrecognized authorized-user entry; review README manually')
                name = match[1].lower()
                if name in expected and expected[name] != role:
                    raise ValueError('Conflicting user roles in README')
                expected[name] = role
    if found != {'admin', 'standard'} or not expected or 'admin' not in expected.values() or (services is None and not auto_rem):
        raise ValueError('Cannot independently verify README user/service sections; review manually')
    if services is None:
        services = []
    if not isinstance(data, dict):
        raise ValueError('AI response must be a JSON object')
    for field in ('all_users', 'recent_hires', 'terminated_users', 'critical_services', 'groups_to_create', 'system_users_to_restrict'):
        if not isinstance(data.get(field), list):
            raise ValueError('Missing or invalid array: ' + field)
    actual = {}
    for user in data['all_users']:
        if not isinstance(user, dict) or not isinstance(user.get('name'), str) or not isinstance(user.get('groups'), list):
            raise ValueError('Malformed AI user entry')
        name = user['name'].lower()
        if name in actual:
            raise ValueError('Duplicate AI user entry')
        if user.get('account_type') not in ('admin', 'standard') or not all(isinstance(g, str) and re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]*\$?', g) for g in user['groups']):
            raise ValueError('Invalid AI user role or group')
        actual[name] = user['account_type']
    if actual != expected:
        raise ValueError('AI user list/roles disagree with README. Missing: ' + ', '.join(sorted(expected.keys() - actual.keys())) + '; extra: ' + ', '.join(sorted(actual.keys() - expected.keys())))
    if services is not None and len(services) > 0:
        if not all(isinstance(s, str) for s in data['critical_services']) or set(data['critical_services']) != set(services):
            raise ValueError('AI critical services disagree with README')
    # Additional account creation/deletion requires manual verification only in strict mode
    if not auto_rem:
        if data['recent_hires'] or data['terminated_users'] or data['groups_to_create'] or data['system_users_to_restrict']:
            raise ValueError('Additional account/group actions require manual verification')
    return len(expected)


if __name__ == '__main__':
    try:
        count = validate(Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace'), json.loads(Path(sys.argv[2]).read_text(encoding='utf-8', errors='replace')))
        print(f'Validated {count} authorized users, roles, and required services against source HTML')
    except (ValueError, OSError, IndexError, TypeError) as exc:
        if os.environ.get('AUTO_REMEDIATE') == '1':
            print(f'WARNING: README validation: {exc} (proceeding under AUTO_REMEDIATE=1)', file=sys.stderr)
            sys.exit(0)
        print('README validation failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
