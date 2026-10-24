"""Remove privileges from byte-identical local copies only under explicit policy.

Custom helpers and package binaries are preserved for review. Use open file
descriptors for checks and mutations so swapping a pathname cannot redirect them.
"""
import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

REFERENCES=('find','bash','dash','python3','perl','ruby','awk','tar','vim','cp','env')


def digest(fd):
    os.lseek(fd,0,os.SEEK_SET)
    h=hashlib.sha256()
    while True:
        chunk=os.read(fd,131072)
        if not chunk: break
        h.update(chunk)
    return h.hexdigest()


def apply_policy(root, explicit, journal=None):
    if not explicit: return []
    root=Path(root); hashes=set();results=[]
    for name in REFERENCES:
        path=root/'usr/bin'/name
        try:
            with path.open('rb') as stream: hashes.add(hashlib.sha256(stream.read(64_000_000)).hexdigest())
        except OSError: continue
    base=root/'usr/local';deadline=time.monotonic()+10;entries=0
    for parent,dirs,files in os.walk(base,followlinks=False):
        dirs[:]=[name for name in dirs if not (Path(parent)/name).is_symlink()]
        for name in files:
            entries+=1
            if entries>10000 or time.monotonic()>deadline:
                raise RuntimeError('Privilege policy budget reached; remaining files require review')
            path=Path(parent)/name
            if path.is_symlink(): continue
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                metadata=os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>64_000_000 or metadata.st_nlink!=1: continue
                actual=Path(os.readlink(f'/proc/self/fd/{fd}'))
                if base.resolve() not in actual.parents: continue
                try: cap=os.getxattr(fd,'security.capability')
                except OSError as error:
                    if error.errno not in (errno.ENODATA,errno.ENOTSUP): raise
                    cap=b''
                if not (metadata.st_mode & 0o6000 or cap): continue
                checksum=digest(fd)
                if checksum not in hashes: continue
                record={'path':str(path),'sha256':checksum,'original_mode':stat.S_IMODE(metadata.st_mode),
                        'capability_xattr':base64.b64encode(cap).decode(),'status':'planned'}
                # Save restore metadata before touching the inode.
                results.append(record)
                if journal: journal(results)
                if cap: os.removexattr(fd,'security.capability')
                os.fchmod(fd,stat.S_IMODE(metadata.st_mode)&~0o6000)
                record['status']='applied'
                if journal: journal(results)
            finally: os.close(fd)
    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readme',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Root required')
    text=args.readme.read_text(errors='replace')
    explicit=bool(re.search(r'no\s+extra\s+SUID\s+or\s+interpreter\s+capabilities\s+are\s+authorized',text,re.I))
    os.umask(0o077)
    previous=json.loads(args.report.read_text()) if args.report.exists() else []
    def journal(records):
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(previous+records,indent=2)+'\n')
    records=apply_policy(Path('/'),explicit,journal)
    journal(records)
    print(f'Explicit privilege policy: {len(records)} local copies changed; unrelated helpers preserved for review')
