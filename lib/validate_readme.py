"""Cross-check AI account/service extraction against explicit HTML README lists."""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path


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


def validate(html, data):
    parser = Sections()
    parser.feed(html)
    expected = {}
    services = None
    found = set()
    for heading, chunks in parser.sections:
        heading = heading.lower().strip().rstrip(':')
        role = None
        if heading.startswith('authorized administrator'):
            role = 'admin'
        elif heading in ('authorized users', 'authorized user'):
            role = 'standard'
        elif heading in ('critical services', 'required services'):
            services = []
            for line in ''.join(chunks).splitlines():
                line = line.strip().lower()
                if not line:
                    continue
                name = re.match(r'[a-z0-9_-]+', line)
                if not name:
                    raise ValueError('Unrecognized required service entry; review README manually')
                services.append({'openssh-server': 'ssh', 'sshd': 'ssh'}.get(name[0], name[0]))
        if role:
            if role in found:
                raise ValueError('Multiple authorized-user sections; review README manually')
            found.add(role)
            for line in ''.join(chunks).splitlines():
                line = line.strip()
                if not line:
                    continue
                match = re.fullmatch(r'([a-z_][a-z0-9_-]*\$?)(?:\s*:\s*.*|\s*\([^\n]*\))?', line)
                if not match:
                    raise ValueError('Unrecognized authorized-user entry; review README manually')
                name = match[1]
                if name in expected and expected[name] != role:
                    raise ValueError('Conflicting user roles in README')
                expected[name] = role
    if found != {'admin', 'standard'} or not expected or 'admin' not in expected.values() or services is None:
        raise ValueError('Cannot independently verify README user/service sections; review manually')
    if not isinstance(data, dict):
        raise ValueError('AI response must be a JSON object')
    for field in ('all_users', 'recent_hires', 'terminated_users', 'critical_services', 'groups_to_create', 'system_users_to_restrict'):
        if not isinstance(data.get(field), list):
            raise ValueError('Missing or invalid array: ' + field)
    actual = {}
    for user in data['all_users']:
        if not isinstance(user, dict) or not isinstance(user.get('name'), str) or not isinstance(user.get('groups'), list):
            raise ValueError('Malformed AI user entry')
        name = user['name']
        if name in actual:
            raise ValueError('Duplicate AI user entry')
        if user.get('account_type') not in ('admin', 'standard') or not all(isinstance(g, str) and re.fullmatch(r'[a-z_][a-z0-9_-]*\$?', g) for g in user['groups']):
            raise ValueError('Invalid AI user role or group')
        actual[name] = user['account_type']
    if actual != expected:
        raise ValueError('AI user list/roles disagree with README. Missing: ' + ', '.join(sorted(expected.keys() - actual.keys())) + '; extra: ' + ', '.join(sorted(actual.keys() - expected.keys())))
    if not all(isinstance(s, str) for s in data['critical_services']) or set(data['critical_services']) != set(services):
        raise ValueError('AI critical services disagree with README')
    # Additional AI-directed account creation/deletion is not inferred from these lists.
    if data['recent_hires'] or data['terminated_users'] or data['groups_to_create'] or data['system_users_to_restrict']:
        raise ValueError('Additional account/group actions require manual verification')
    return len(expected)


if __name__ == '__main__':
    try:
        count = validate(Path(sys.argv[1]).read_text(encoding='utf-8'), json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')))
        print(f'Validated {count} authorized users, roles, and required services against source HTML')
    except (ValueError, OSError, IndexError, TypeError) as exc:
        print('README validation failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
