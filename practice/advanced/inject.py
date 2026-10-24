#!/usr/bin/env python3
"""A business inject: onboard an authorized intern without breaking the ledger.

Run --issue after the initial hardening pass, rerun the hardener against the
updated README, then --score. This models a changing requirement, not malware.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


def score(seed):
    name=f'intern{seed}';group=f'research{seed}'
    result=[]
    user=subprocess.run(['getent','passwd',name],capture_output=True,text=True)
    fields=user.stdout.strip().split(':')
    result.append({'check':'authorized-intern-exists','pass':user.returncode==0 and len(fields)==7})
    groups=subprocess.run(['id','-nG',name],capture_output=True,text=True).stdout.split()
    result.append({'check':'required-project-group','pass':group in groups})
    result.append({'check':'least-privilege','pass':bool(groups) and not set(groups).intersection({'sudo','admin','root','docker','lxd','disk','shadow'})})
    status=subprocess.run(['passwd','-S',name],capture_output=True,text=True).stdout.split()
    result.append({'check':'nonempty-password','pass':len(status)>1 and status[1]=='P'})
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,required=True)
    parser.add_argument('--issue',action='store_true')
    parser.add_argument('--score',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not 1<=args.seed<=9999: parser.error('Invalid seed')
    if os.geteuid()!=0 or not Path('/etc/cp-advanced-lab').is_file():
        raise SystemExit('Disposable lab guest only')
    if Path('/var/lib/cp-lab-seed').read_text().strip()!=str(args.seed):
        raise SystemExit('Seed mismatch')
    if args.issue:
        path=Path('/home/cpoperator/Desktop/README.md')
        text=path.read_text()
        marker=f'New Hires:\nintern{args.seed} (groups: research{args.seed})'
        if marker not in text: path.write_text(text+'\n\n'+marker+'\n')
        print('Business request issued: create the intern, retain required group access, no administrator privileges.')
    if args.score:
        results=score(args.seed)
        if args.output: args.output.write_text(json.dumps(results,indent=2)+'\n')
        print(f'{sum(r["pass"] for r in results)}/{len(results)} business-inject checks passed')
