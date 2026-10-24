"""Small preserving service changes, with daemon validation and rollback.

Do not replace a working business configuration with an unrelated template.
Unsupported layouts fail for review rather than silently rebuilding the service.
"""
import argparse
import configparser
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import stat


def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=60)
    if p.returncode:
        raise RuntimeError(' '.join(args[:3])+': '+(p.stdout+p.stderr)[-1800:])
    return p.stdout


def pg_settings(text, values):
    marker='# BEGIN CP POSTGRES POLICY'
    clean=re.sub(r'(?ms)^# BEGIN CP POSTGRES POLICY\n.*?^# END CP POSTGRES POLICY\n?', '',text)
    # Leave all unrelated paths, includes, replication and application settings.
    keys='|'.join(re.escape(k) for k in values)
    clean=re.sub(r'(?m)^\s*(?:'+keys+r')\s*=.*\n?', '',clean)
    return clean.rstrip()+'\n'+marker+'\n'+''.join(f'{k} = {v}\n' for k,v in values.items())+'# END CP POSTGRES POLICY\n'


def pg_hba(text):
    lines=[]
    for line in text.splitlines(keepends=True):
        parts=line.split('#',1)[0].split()
        index=3 if parts and parts[0]=='local' else 4
        if len(parts)>index and parts[index]=='trust':
            # Peer enforces the OS identity and preserves local service access.
            method='peer' if parts[0]=='local' else 'scram-sha-256'
            field=list(re.finditer(r'\S+',line.split('#',1)[0]))[index]
            line=line[:field.start()]+method+line[field.end():]
        lines.append(line)
    return ''.join(lines)


def nginx_text(text):
    # Migrate only our previous generated header; never remove operator policy.
    text=re.sub(r'(?ms)(# BEGIN CP NGINX SERVER\n)(.*?)(# END CP NGINX SERVER)',
                lambda m:m[1]+m[2].replace('add_header X-Content-Type-Options nosniff always;\n','')+m[3],text)
    tokens=list(re.finditer(r'#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};#]+',text))
    frames=[];stack=[];statement=[];edits=[]
    for token in tokens:
        val=token.group()
        if val.startswith('#'): continue
        if val=='{':
            frame={'header':[t.group() for t in statement], 'open':token.end(),'directives':[]}
            frames.append(frame);stack.append(frame);statement=[]
        elif val=='}':
            if not stack: raise ValueError('Unbalanced nginx block')
            stack.pop()['close']=token.start();statement=[]
        elif val==';':
            if stack and statement: stack[-1]['directives'].append(statement)
            if len(statement)>=2 and statement[0].group() in ('server_tokens','autoindex'):
                edits.append((statement[1].start(),statement[1].end(),'off'))
            statement=[]
        else:
            statement.append(token)
    if stack: raise ValueError('Unbalanced nginx block')
    for f in frames:
        header=f['header']
        # A new add_header at a child scope suppresses every inherited header.
        # Set the default at http scope; extend child scopes only where they
        # already own their header list. Includes keep their inheritance intact.
        directives=f['directives']
        if (header==['http'] or any(d[0].group()=='add_header' for d in directives)) and not any(
                'X-Content-Type-Options' in [t.group().strip('\"\'') for t in d] for d in directives):
            edits.append((f['open'],f['open'],'\nadd_header X-Content-Type-Options nosniff always;\n'))
        if header==['server']:
            direct=[d[0].group() for d in f['directives']]
            # The marker is local to this server, not another virtual host.
            segment=text[f['open']:f['close']]
            if '# BEGIN CP NGINX SERVER' not in segment:
                block='\n# BEGIN CP NGINX SERVER\n'
                if 'server_tokens' not in direct: block+='server_tokens off;\n'
                block+='location ~ /\\.(?!well-known(?:/|$)) { deny all; }\n# END CP NGINX SERVER\n'
                edits.append((f['open'],f['open'],block))
        if len(header)>=3 and header[:2]==['location','='] and re.match(r'^/\.(?!well-known(?:/|$))',header[2].strip('\"\'')):
            if '# CP deny hidden exact' not in text[f['open']:f['close']]:
                edits.append((f['open'],f['open'],'\n# CP deny hidden exact\nreturn 403;\n'))
    for start,end,replacement in sorted(edits,reverse=True):
        text=text[:start]+replacement+text[end:]
    return text


def samba_text(text, groups):
    clean=re.sub(r'(?ms)^# BEGIN CP SAMBA POLICY\n.*?^# END CP SAMBA POLICY\n?', '',text)
    block='\n# BEGIN CP SAMBA POLICY\n[global]\nserver min protocol = SMB2_02\nmap to guest = Never\nusershare allow guests = no\nrestrict anonymous = 2\n'
    for share,group in groups.items():
        if not re.fullmatch(r'[\w .$-]+',share): raise ValueError('Unsupported share name')
        block+=f'[{share}]\nguest ok = no\n'
        if group:
            if not re.fullmatch(r'[a-z_][a-z0-9_.-]*\$?',group): raise ValueError('Invalid share group')
            block+=f'valid users = @{group}\n'
    return clean.rstrip()+'\n'+block+'# END CP SAMBA POLICY\n'


class Transaction:
    def __init__(self): self.original={}

    def write(self,path,text):
        path=Path(path)
        if path.is_symlink(): path=path.resolve()
        if path not in self.original:
            self.original[path]=(path.read_bytes(),path.stat())
            backup=Path('/var/backups/cyberpatriot/service-policy')/str(time.time_ns())
            backup.mkdir(parents=True,mode=0o700)
            shutil.copy2(path,backup/path.name)
        metadata=path.stat()
        fd, name=tempfile.mkstemp(prefix='.cp-policy-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as stream: stream.write(text)
            os.chmod(name,metadata.st_mode & 0o777)
            os.chown(name,metadata.st_uid,metadata.st_gid)
            os.replace(name,path)
        finally:
            if os.path.exists(name): os.unlink(name)

    def restore(self):
        for path,(data,metadata) in self.original.items():
            path.write_bytes(data);path.chmod(metadata.st_mode & 0o777)
            os.chown(path,metadata.st_uid,metadata.st_gid)


def secure_webroots(roots):
    deadline=time.monotonic()+10;entries=0
    for root in roots:
        root=Path(root)
        if root.is_symlink() or not root.is_dir(): continue
        if len(root.resolve().parts)<3: raise ValueError('Overbroad web root needs manual review')
        for parent,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[name for name in dirs if not (Path(parent)/name).is_symlink()]
            for path in [Path(parent)]+[Path(parent)/name for name in files]:
                entries+=1
                if entries>10000 or time.monotonic()>deadline:
                    raise RuntimeError('Web permission walk reached its budget')
                if path.is_symlink(): continue
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    metadata=os.fstat(fd)
                    if (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)) and metadata.st_mode & 0o002:
                        os.fchmod(fd,stat.S_IMODE(metadata.st_mode)&~0o002)
                finally: os.close(fd)


def nginx():
    binary=shutil.which('nginx')
    if not binary: return
    dump=run([binary,'-T'])
    files=list(dict.fromkeys(re.findall(r'^# configuration file (/.+):$',dump,re.M)))
    tx=Transaction();roots=set()
    try:
        for file in files:
            path=Path(file)
            text=path.read_text()
            roots.update(re.findall(r'(?m)^[ \t]*root\s+(/[^\s;$]+)\s*;',text))
            tx.write(path,nginx_text(text))
        run([binary,'-t'])
        secure_webroots(roots)
        run(['systemctl','reload-or-restart','nginx'])
        run(['systemctl','is-active','nginx'])
    except BaseException:
        tx.restore()
        subprocess.run(['systemctl','restart','nginx'],capture_output=True)
        raise


def postgres():
    if not shutil.which('pg_lsclusters'): return
    import json
    clusters=json.loads(run(['pg_lsclusters','--json']))
    for cluster in clusters:
        version=str(cluster['version']);name=cluster['cluster']
        if not re.fullmatch(r'[0-9.]+',version) or not re.fullmatch(r'[\w-]+',name):
            raise ValueError('Invalid PostgreSQL cluster identity')
        directory=Path('/etc/postgresql')/version/name
        config=directory/'postgresql.conf';hba=directory/'pg_hba.conf'
        values={'password_encryption':"'scram-sha-256'",'log_connections':'on','log_disconnections':'on'}
        readme=Path(os.environ.get('README_FILE',str(Path(__file__).resolve().parents[1]/'data/auto-source.html')))
        text=readme.read_text(errors='replace') if readme.exists() else ''
        configured=os.environ.get('PG_LISTEN_ADDRESSES')
        if configured:
            if not re.fullmatch(r'[\w.*,: -]+',configured): raise ValueError('Invalid PostgreSQL listen address')
            values['listen_addresses']="'"+configured+"'"
        elif re.search(r'(postgres(?:ql)?|database).{0,80}(local.only|localhost.only)',text,re.I):
            values['listen_addresses']="'localhost'"
        tx=Transaction()
        try:
            tx.write(config,pg_settings(config.read_text(),values))
            tx.write(hba,pg_hba(hba.read_text()))
            auto=Path(cluster['pgdata'])/'postgresql.auto.conf'
            if auto.exists():
                # ALTER SYSTEM has precedence over the main configuration.
                tx.write(auto,pg_settings(auto.read_text(),values))
            binary=f'/usr/lib/postgresql/{version}/bin/postgres'
            run(['runuser','-u','postgres','--',binary,'-D',cluster['pgdata'],'-c','config_file='+str(config),'-C','data_directory'])
            run(['pg_ctlcluster',version,name,'restart'])
            run(['pg_isready','-p',str(cluster['port'])])
            run(['runuser','-u','postgres','--','psql','-p',str(cluster['port']),'-wAtqc','SELECT 1'])
        except BaseException:
            tx.restore()
            subprocess.run(['pg_ctlcluster',version,name,'restart'],capture_output=True)
            raise


def samba():
    import grp
    if not shutil.which('testparm'): return
    effective=run(['testparm','-s'])
    parser=configparser.ConfigParser(interpolation=None,strict=False)
    parser.read_string(effective)
    role=parser.get('global','server role',fallback='standalone server').lower()
    if 'domain controller' in role or 'member server' in role:
        raise ValueError('Domain Samba role requires a role-specific review; configuration preserved')
    groups={}
    for section in parser.sections():
        if section.lower()=='global': continue
        group=''
        existing=parser.get(section,'valid users',fallback='')
        if re.fullmatch(r'@[a-z_][a-z0-9_.-]*\$?',existing): group=existing[1:]
        path=parser.get(section,'path',fallback='')
        if not existing and path and '%' not in path and Path(path).is_dir():
            owner_group=grp.getgrgid(Path(path).stat().st_gid).gr_name
            if owner_group!='root': group=owner_group
        groups[section]=group
    path=Path('/etc/samba/smb.conf');tx=Transaction()
    try:
        tx.write(path,samba_text(path.read_text(),groups))
        run(['testparm','-s'])
        run(['systemctl','restart','smbd'])
        run(['systemctl','is-active','smbd'])
    except BaseException:
        tx.restore();subprocess.run(['systemctl','restart','smbd'],capture_output=True)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service',choices=['nginx','postgres','samba'])
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Root required')
    globals()[args.service]()
