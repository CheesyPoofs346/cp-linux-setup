#!/usr/bin/env python3
"""Read-only business checks from a separate observer VM, never localhost."""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import urllib.request


def probe(target,seed,key,known_hosts):
    address=ipaddress.ip_address(target)
    if not address.is_private or address.is_loopback:
        raise ValueError('Expected the private address of the isolated lab guest')
    if not 1<=seed<=9999: raise ValueError('Invalid seed')
    results=[]
    def check(name,func):
        try:
            detail=func();results.append({'check':name,'pass':True,'detail':str(detail)})
        except Exception as error:
            results.append({'check':name,'pass':False,'detail':str(error)[:1000]})
    token=f'RESEARCH-DATA-{seed}-KEEP'
    def http(path):
        with urllib.request.urlopen(f'http://{target}/{path}',timeout=10) as response:
            body=response.read(4096).decode()
        if token not in body: raise ValueError('Ledger missing')
        return 'Expected ledger returned'
    check('web',lambda:http(''))
    check('web-api-database-chain',lambda:http('api/'))
    ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes',
         '-o','UserKnownHostsFile='+str(known_hosts),'-i',str(key)]
    def command(args,denied=False):
        result=subprocess.run(args,capture_output=True,text=True,timeout=20)
        if denied:
            if result.returncode==0 or 'Permission denied' not in result.stderr:
                raise ValueError('Expected explicit authentication rejection, not a network error')
        elif result.returncode:
            raise ValueError(result.stderr[-1000:])
        return (result.stdout+result.stderr)[-500:]
    check('operator-ssh-login',lambda:command(ssh+[f'cpoperator@{target}','id -un']))
    check('root-ssh-rejected',lambda:command(ssh+[f'root@{target}','true'],True))
    check('authenticated-share',lambda:command(['smbclient',f'//{target}/projects{seed}',
        '-U',f'analyst{seed}%Practice-Only-{seed}!Secure','-c','get ledger.txt /dev/null']))
    def db_closed():
        with socket.socket() as connection:
            connection.settimeout(3)
            if connection.connect_ex((target,5432))==0:
                raise ValueError('Local-only PostgreSQL exposed to observer')
        return 'Remote database connection unavailable as required'
    check('database-local-only',db_closed)
    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True)
    parser.add_argument('--seed',type=int,required=True)
    parser.add_argument('--key',type=Path,required=True)
    parser.add_argument('--known-hosts',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=probe(args.target,args.seed,args.key,args.known_hosts)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f'{sum(r["pass"] for r in result)}/{len(result)} observer checks passed')
