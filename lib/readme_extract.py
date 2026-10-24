"""Deterministic CyberPatriot README extraction (no AI).

Emits the readme_parsed.json schema the modules consume. Users/admins/services
come from the README's explicit sections; hires, terminations and group tasks
come from headed lists and the common sentence patterns. Anything the README
mentions that this parser cannot structure is reported in `unparsed_hints` so
the caller can ask AI for just those gaps.

Usage: readme_extract.py README.html OUT.json   (exit 0 ok, 3 = no user sections)
"""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

NAME = r'[a-zA-Z_](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9_-])?\$?'
SERVICE_ALIASES = {'openssh-server': 'ssh', 'sshd': 'ssh', 'openssh': 'ssh', 'apache': 'apache2',
                   'httpd': 'apache2', 'mariadb': 'mysql', 'samba': 'smbd', 'smb': 'smbd',
                   'proftpd': 'proftpd', 'vsftpd': 'vsftpd', 'postgresql': 'postgresql'}
SKIP_PREFIX = ('none', 'n/a', 'note', 'do not', 'all other', 'these users', 'the following', 'only')


def html_to_lines(html, mark_headings=False):
    """Visible text, one logical line per block element."""
    class P(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.out, self.skip = [], 0
        def handle_starttag(self, tag, attrs):
            if tag in ('script', 'style'):
                self.skip += 1
            elif re.fullmatch(r'h[1-6]', tag):
                self.out.append('\n' + ('@@HEADING@@' if mark_headings else ''))
            elif tag in ('br', 'p', 'li', 'tr', 'div', 'pre', 'ul', 'ol', 'table'):
                self.out.append('\n')
            elif tag in ('td', 'th'):
                self.out.append(' ')
        def handle_endtag(self, tag):
            if tag in ('script', 'style'):
                self.skip = max(0, self.skip - 1)
            elif tag in ('p', 'li', 'tr', 'div', 'pre', 'ul', 'ol', 'table') or re.fullmatch(r'h[1-6]', tag):
                self.out.append('\n')
        def handle_data(self, data):
            if not self.skip:
                self.out.append(data)
    p = P()
    p.feed(html)
    return [re.sub(r'[ \t\xa0]+', ' ', l).strip() for l in ''.join(p.out).splitlines() if l.strip()]


def section_kind(line):
    low = re.sub(r'^[#*_\-\s]+', '', line).strip().rstrip(':').lower()
    low = re.sub(r'\([^)]*\)', '', low).strip()
    if re.fullmatch(r'(authorized )?administrators?(?: and (?:authorized )?users?)?', low):
        return 'admin'
    if re.fullmatch(r'authorized users?', low) or low in ('users', 'standard users'):
        return 'standard'
    if re.fullmatch(r'(critical|required) services?', low) or low == 'services':
        return 'services'
    if re.match(r'^(terminated|former|fired|unauthorized|removed)\b.*\b(users?|employees?|accounts?|staff)\b', low):
        return 'terminated'
    if re.match(r'^(new|recent|recently added|newly (hired|added))\b.*\b(hires?|users?|employees?|members?|accounts?)\b', low):
        return 'hires'
    return None


LABELS = {'password', 'passwd', 'pass', 'pw', 'username', 'user', 'users', 'name', 'account', 'accounts', 'you', 'note', 'notes', 'admin', 'administrator',
          'administrators', 'standard', 'group', 'groups', 'authorized', 'the', 'a', 'an', 'this', 'all', 'also'}
STOPWORDS = {'the', 'this', 'that', 'our', 'all', 'any', 'each', 'every', 'these', 'those', 'your', 'an', 'a', 'it', 'which', 'what', 'company', 'system',
             'her', 'him', 'them', 'his', 'hers', 'she', 'he', 'they', 'for', 'new', 'and', 'with', 'named', 'called', 'user', 'account', 'employee'}


def entry_name(line):
    clean = re.sub(r'^[\s*\-•#>\d.)]+', '', line).strip()
    low = clean.lower()
    if not clean or low.startswith(SKIP_PREFIX):
        return None, clean
    m = re.fullmatch('(' + NAME + r')(?:\s*:\s*\S+)?(?:\s*\([^)]*\))*\s*', clean)
    name = m[1].lower() if m else None
    return (None if name in LABELS else name), clean


def sentences(text):
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+|\n', text) if s.strip()]


def prose_services(text):
    """Critical services/programs named in sentences ("OpenSSH is a critical service", "Chromium must remain")."""
    found = []
    def add(token):
        token = re.sub(r'[^a-z0-9_.+-]', '', token.lower().strip())
        token = SERVICE_ALIASES.get(token, token)
        if token and token not in STOPWORDS and len(token) > 2 and token not in found:
            found.append(token)
    for s in sentences(text):
        for m in re.finditer(r'([A-Za-z][\w.+-]*)(?:\s+(?:server|service|daemon))?\s+(?:is|are)\s+(?:a\s+|an\s+|the\s+)?(?:critical|required|essential|key|important)\s+service', s, re.I):
            add(m[1])
        m = re.search(r'critical services?\s*(?:are|is|include|includes)\s*:?\s*([^.]+)', s, re.I)
        if m:
            for part in re.split(r',|\band\b', m[1]):
                words = re.findall(r'[A-Za-z][\w.+-]*', part)
                if words:
                    add(words[0])
        for m in re.finditer(r'(?:requires?|needs?|relies on|depends on|must (?:keep|run|have))\s+(?:the\s+)?(?:an?\s+)?([A-Za-z][\w.+-]*)\s+(?:server|service|daemon)', s, re.I):
            add(m[1])
        for m in re.finditer(r'(?:default (?:web )?browser (?:is|=)\s+|browser,?\s+)([A-Za-z][\w.+-]*)', s, re.I):
            if re.search(r'must|remain|keep|required|default', s, re.I):
                add(m[1])
        m = re.search(r'([A-Za-z][\w.+-]*)\s+(?:is|are)\s+(?:the\s+)?(?:default|company[- ]approved|required)\s+(?:web\s+)?(?:browser|firewall|mail|email)', s, re.I)
        if m:
            add(m[1])
    return found


def prose_accounts(text):
    """Hires, demotions, promotions and terminations written as sentences."""
    hires, demote, promote, terminated = [], set(), set(), []
    user = r'([a-z][a-z0-9_-]{2,30})'
    for s in sentences(text):
        low = s.lower()
        if re.search(r'new (hire|employee|user|member|administrator|admin)|(has|have) been hired|recently (hired|added)|create (an |a |the )?(new )?(user |admin\w* )?account|should have an account|needs? an account', low):
            names = [n.lower() for n in re.findall(r'\(' + user + r'\)', s, re.I)]
            if not names:
                names = [n.lower() for n in re.findall(r'(?:user(?:name)?|account(?: for| named| called)?)\s+["“\']?' + user, s, re.I)]
            for n in names:
                if n not in LABELS and n not in STOPWORDS and n != 'you' and n not in [h['name'] for h in hires]:
                    admin = bool(re.search(r'\b(?:as\s+(?:an?\s+)?|new\s+)admin|\badmin(?:istrator)?\s+account', low)) and not re.search(r'\bnot\s+(?:an?\s+)?admin', low)
                    hires.append({'name': n, 'account_type': 'admin' if admin else 'standard', 'groups': []})
        for m in re.finditer(r'\b' + user + r'\b(?:\s*\([^)]*\))?\s+(?:is|are|should be|shall be)\s+(?:no longer|not)\s+(?:an?\s+)?admin', low):
            demote.add(m[1])
        for m in re.finditer(r'\b' + user + r'\b\s+(?:should|must|needs to)\s+be\s+(?:an?\s+)?admin', low):
            promote.add(m[1])
        for m in re.finditer(r'\b' + user + r'\b(?:\s*\([^)]*\))?\s+(?:has|have|was|were)\s+(?:been\s+)?(?:terminated|fired|let go|dismissed)|\b' + user + r'\b\s+(?:no longer works|has left the company|left the company)', low):
            n = m[1] or m[2]
            if n and n not in terminated and n not in STOPWORDS:
                terminated.append(n)
    return hires, demote, promote, terminated


def groups_in(clean):
    m = re.search(r'\bgroups?\s*[:=]?\s*([A-Za-z0-9_,\s-]+)', clean, re.I)
    return sorted({g.lower() for g in re.split(r'[,\s]+', m[1]) if re.fullmatch(NAME, g) and g.lower() != 'and'}) if m else []


def extract(html):
    raw_lines = html_to_lines(html, mark_headings=True)
    lines = [line.removeprefix('@@HEADING@@') for line in raw_lines]
    text = '\n'.join(lines)
    users, hires, terminated, services, passwords = {}, [], [], [], {}
    warnings = []
    kind = None
    last_user = None
    for raw_line, line in zip(raw_lines, lines):
        header = re.split(r':(?![^()]*\))', line, maxsplit=1)
        k = section_kind(header[0])
        if k:
            kind = k
            last_user = None
            if len(header) == 1 or not header[1].strip():
                continue
            line = header[1].strip()
        elif raw_line.startswith('@@HEADING@@'):
            if re.match(r'authorized (users?|administrators?)\b', line, re.I):
                warnings.append('unparsed_accounts')
            if re.match(r'(required|critical) services?\b', line, re.I) and not prose_services(line):
                warnings.append('unparsed_services')
            kind = None
            last_user = None
            continue
        if line.lower().rstrip(':') in ('competition guidelines', 'forensics questions', 'unique identifier'):
            kind = None
            last_user = None
            continue
        pw_line = re.match(r'^[\s*\-•]*(?:password|passwd|pass|pw)\s*[:=]\s*(\S+)', line, re.I)
        if pw_line and last_user and kind in ('admin', 'standard'):
            passwords[last_user] = pw_line[1]
            continue
        if kind in ('admin', 'standard') and line.rstrip().endswith('.') and not line.startswith(('-', '*', '•')) and (len(line.split()) >= 8 or re.search(r'\b(is|are|must|should|requires?|needs?)\b', line, re.I)):
            kind = None   # a full sentence ends the list
            continue
        if re.match(r'^(forensics|competition|important|scoring|scenario|unique identifier|this is|the .* (policy|computer))', line, re.I) \
                and not line.startswith(('-', '*', '•')) and ' ' in line and kind in ('admin', 'standard', 'services', 'terminated', 'hires') and len(line.split()) > 6:
            kind = None
            continue
        if kind in ('admin', 'standard'):
            if any(prose_accounts(line)):
                kind = None
                continue
            name, clean = entry_name(line)
            if re.fullmatch(NAME + r'(?:\s*[,;]\s*' + NAME + r')+', clean):
                names = [n.strip().lower() for n in re.split(r'[,;]', clean)]
            else:
                names = [name] if name else []
            if not names and clean and not clean.lower().startswith(SKIP_PREFIX) and clean.lower() not in LABELS:
                warnings.append('unparsed_accounts')
            for name in names:
                if name in users and users[name]['account_type'] != kind:
                    warnings.append('conflicting_account_roles')
                last_user = name
                users[name] = {'name': name, 'account_type': kind, 'groups': groups_in(clean)}
                pw = re.fullmatch(NAME + r'\s*:\s*(\S+)(?:\s*\(.*\))?', clean)
                if pw:
                    passwords[name] = pw[1]
        elif kind == 'services':
            clean = re.sub(r'^[\s*\-•#>\d.)]+', '', line).strip().lower()
            if clean and not clean.startswith(SKIP_PREFIX):
                for part in re.split(r'[,;]|\band\b', clean):
                    token = re.search(r'[a-z0-9_.-]+', part)
                    if not token:
                        continue
                    paren = re.findall(r'\(([a-z0-9_.-]+)\)', part)
                    for s in ([token[0]] + paren):
                        s = s.removesuffix('.service')
                        s = SERVICE_ALIASES.get(s, s)
                        if s not in services:
                            services.append(s)
        elif kind == 'terminated':
            name, _ = entry_name(line)
            if name:
                terminated.append(name)
        elif kind == 'hires':
            name, clean = entry_name(line)
            if name:
                hires.append({'name': name, 'account_type': 'admin' if re.search(r'\badmin', clean, re.I) else 'standard',
                              'groups': groups_in(clean)})

    p_hires, p_demote, p_promote, p_terminated = prose_accounts(text)
    if p_demote & p_promote:
        warnings.append('conflicting_account_roles')
    known_role_targets = set(users) | {h['name'] for h in hires + p_hires}
    if (p_demote | p_promote) - known_role_targets:
        warnings.append('unknown_account_role_target')
    for sentence in sentences(text):
        if re.search(r'no longer[^.]*admin|\bnot\b[^.]{0,30}\badmin|\bdemot\w*|\bpromot\w*|admin(?:istrator)?\s+privileges', sentence, re.I):
            new_hires, demotions, promotions, _ = prose_accounts(sentence)
            if new_hires and re.search(r'as an? (?:standard|regular) user', sentence, re.I) and re.search(r'not an? admin', sentence, re.I):
                continue
            if not demotions and not promotions:
                warnings.append('unparsed_account_roles')
    for h in p_hires:
        if h['name'] not in users and h['name'] not in [x['name'] for x in hires]:
            hires.append(h)
    for name in p_demote:
        if name in users:
            users[name]['account_type'] = 'standard'
        for hire in hires:
            if hire['name'] == name:
                hire['account_type'] = 'standard'
    for name in p_promote:
        if name in users:
            users[name]['account_type'] = 'admin'
        for hire in hires:
            if hire['name'] == name:
                hire['account_type'] = 'admin'
    terminated += [t for t in p_terminated if t not in users]
    for s in prose_services(text):
        if s not in services:
            services.append(s)

    groups_to_create = []
    for m in re.finditer(r'create (?:a |the )?(?:new )?group\s+(?:called |named )?["“\']?(' + NAME + r')["”\']?\s*(?:and|,)?\s*(?:add|with|containing|including)?[^.\n]*?(?:users?|members?)?[:\s]+((?:' + NAME + r'(?:\s*,\s*(?:and\s+)?|\s+and\s+))*' + NAME + r')', text, re.I):
        members = [x.lower() for x in re.split(r'\s*,\s*|\s+and\s+', m[2]) if re.fullmatch(NAME, x.strip())]
        groups_to_create.append({'name': m[1].lower(), 'members': members})

    hints = list(dict.fromkeys(warnings))
    checks = (('terminat|former employee|no longer (work|employ)|should be removed', 'terminated_users', bool(terminated)),
              (r'new (hire|employee|user|member)|recently (hired|added)|(needs?|should have) an? account', 'recent_hires', bool(hires)),
              (r'create (a |the )?(new )?group', 'groups_to_create', bool(groups_to_create)),
              (r'restrict(ed)? (login|access)|nologin|system (user|account)s? .*(login|shell)', 'system_users_to_restrict', False))
    for pattern, field, captured in checks:
        if not captured and re.search(pattern, text, re.I):
            hints.append(field)

    return {'all_users': list(users.values()), 'recent_hires': hires, 'terminated_users': sorted(set(terminated)),
            'critical_services': services, 'groups_to_create': groups_to_create, 'system_users_to_restrict': [],
            'passwords': passwords, 'unparsed_hints': hints}


if __name__ == '__main__':
    data = extract(Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace'))
    if not data['all_users'] or not any(u['account_type'] == 'admin' for u in data['all_users']):
        print('no authorized user/admin sections found', file=sys.stderr)
        sys.exit(3)
    Path(sys.argv[2]).write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(f"Deterministic README parse: {len(data['all_users'])} users, {len(data['critical_services'])} services"
          + (f"; unparsed hints: {','.join(data['unparsed_hints'])}" if data['unparsed_hints'] else ''))
