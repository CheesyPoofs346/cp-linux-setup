#!/usr/bin/env python3
"""FIXTURE-SPECIFIC coach actions for the manual remainder, NOT a hardener module.

Use only after reviewing this lab's synthetic artifacts and recording the actual
automated score. This validates that the independent rubric is attainable; it
must never be reported as the general hardener's automated result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,required=True)
    parser.add_argument('--i-reviewed-this-synthetic-fixture',action='store_true')
    args=parser.parse_args()
    if (not args.i_reviewed_this_synthetic_fixture or not 1<=args.seed<=9999 or os.name!='posix'
            or os.geteuid()!=0 or socket.gethostname()!='advanced-cp-lab'
            or not Path('/etc/cp-advanced-lab').is_file()
            or Path('/var/lib/cp-lab-seed').read_text().strip()!=str(args.seed)):
        raise SystemExit('Refusing outside the reviewed synthetic lab')
    n=args.seed;os.umask(0o077)
    directory=Path('/root/coach/reference-quarantine');directory.mkdir(parents=True,exist_ok=True)
    records=[]
    def quarantine(path):
        path=Path(path)
        if not path.exists(): return
        if path.is_symlink() or path.resolve()!=path or not path.is_file():
            raise ValueError('Unexpected fixture path: '+str(path))
        data=path.read_bytes();checksum=hashlib.sha256(data).hexdigest()
        if path.suffix=='.pdf' and not data.startswith(b'\x7fELF'):
            raise ValueError('Expected the synthetic disguised ELF fixture')
        dest=directory/(path.name+'.'+checksum)
        if dest.exists(): raise FileExistsError('Review existing quarantine before proceeding')
        records.append({'source':str(path),'destination':str(dest),'sha256':checksum,'mode':stat.S_IMODE(path.stat().st_mode)})
        path.rename(dest);dest.chmod(0o600)
    subprocess.run(['runuser','-u','postgres','--','psql','-v','ON_ERROR_STOP=1','-c',
                    f'ALTER ROLE analyst{n} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;',
                    '-c','REVOKE CREATE ON SCHEMA public FROM PUBLIC;'],check=True)
    subprocess.run(['systemctl','disable','--now','research-sync.timer'],check=True)
    for path in ('/etc/cron.d/research-sync','/etc/systemd/system/research-sync.timer',
                 '/etc/systemd/system/research-sync.service',
                 f'/home/analyst{n}/.config/systemd/user/research-session.service',
                 f'/home/analyst{n}/Desktop/quarterly_report.pdf'):
        quarantine(path)
    startup=Path(f'/home/analyst{n}/.bashrc')
    original=startup.read_text()
    backup=directory/'original-bashrc'
    if not backup.exists(): backup.write_text(original)
    startup.write_text(''.join(line for line in original.splitlines(keepends=True) if line.strip()!='export LAB_UNAUTHORIZED=1'))
    subprocess.run(['systemctl','daemon-reload'],check=True)
    (directory/'actions.json').write_text(json.dumps(records,indent=2)+'\n')
    print('Coach reference applied. This is manual fixture review, not an automated hardener score.')
