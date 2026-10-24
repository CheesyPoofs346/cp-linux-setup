#!/usr/bin/env python3
"""Windows VMware lab builder/transport. No host network/security changes.

Requires VMware Workstation and pycdlib. Uses guest operations because a Windows
host may not have a VMnet8 adapter. Never rewrites an existing VM definition.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time
import urllib.request

VMWARE = Path('C:/Program Files (x86)/VMware/VMware Workstation')
LAB_PASSWORD = 'Practice-Only-Lab-Admin!42'  # Synthetic, documented lab credential.
BASE = 'https://cloud-images.ubuntu.com/noble/current/'
IMAGE = 'noble-server-cloudimg-amd64.vmdk'


def require_new_vm(root):
    if (root / 'lab.vmx').exists() or (root / 'lab.vmdk').exists():
        raise FileExistsError('Existing VM/disk: use a new directory; never overwrite a snapshot chain')


def command(args, timeout=120):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stdout+p.stderr)[-4000:])
    return p.stdout.strip()


class Guest:
    def __init__(self, root, vmx='lab.vmx'):
        self.root = Path(root).resolve()
        self.vmx = self.root/vmx
        self._elevation_ready = False

    def call(self, operation, *args):
        return command([VMWARE/'vmrun.exe','-gu','cpoperator','-gp',LAB_PASSWORD,
                        operation,self.vmx,*args])

    def run(self, *args, wait=True):
        # Hardening legitimately removes passwordless sudo. Authenticate with the
        # documented lab password instead of depending on NOPASSWD surviving.
        if not self._elevation_ready:
            helper=self.root/'elevate.sh'
            helper.write_text("#!/bin/bash\nprintf '%s\\n' '"+LAB_PASSWORD+"' | sudo -S -p '' -- \"$@\"\n",newline='\n')
            self.upload(helper,'/home/cpoperator/cp-lab-elevate.sh')
            self._elevation_ready=True
        options = [] if wait else ['-noWait']
        return self.call('runProgramInGuest', *options, '/bin/bash','/home/cpoperator/cp-lab-elevate.sh', *args)

    def upload(self, source, destination):
        return self.call('copyFileFromHostToGuest', Path(source).resolve(), destination)

    def download(self, source, destination):
        self.run('/usr/bin/install','-m','644',source,'/tmp/cp-lab-export')
        return self.call('copyFileFromGuestToHost','/tmp/cp-lab-export',Path(destination).resolve())

    def script(self, text):
        path=self.root/'stage.sh'
        path.write_text(text.replace('\r\n','\n'),encoding='utf-8',newline='\n')
        self.upload(path,'/home/cpoperator/cp-lab-stage.sh')
        # Package upgrades may restart VMware guest services. Launch in an
        # independent systemd unit so that cannot kill the run's parent cgroup.
        unit='cp-lab-stage-'+str(time.time_ns())
        return self.run('/usr/bin/systemd-run','--unit='+unit,'--collect',
                        '/bin/bash','/home/cpoperator/cp-lab-stage.sh')


def archive(repo, destination):
    # Explicit exclusions keep local credentials and generated data out of guests.
    with tarfile.open(destination,'w:gz') as tar:
        for file in Path(repo).rglob('*'):
            rel=file.relative_to(repo)
            if (not file.is_file() or any(x in rel.parts for x in ('.git','data','__pycache__','.forensics-venv'))
                    or file.name.startswith('.env') or '.local.' in file.name or file.suffix=='.log'):
                continue
            data=file.read_bytes()
            if file.suffix in ('.sh','.py','.conf','.md','.json'):
                data=data.removeprefix(b'\xef\xbb\xbf').replace(b'\r\n',b'\n')
            info=tarfile.TarInfo(rel.as_posix());info.size=len(data)
            info.mode=0o755 if file.suffix=='.sh' else 0o644
            tar.addfile(info,io.BytesIO(data))


def build(root):
    import pycdlib
    root=Path(root).resolve();require_new_vm(root);root.mkdir(parents=True,exist_ok=True)
    sums=urllib.request.urlopen(BASE+'SHA256SUMS',timeout=60).read().decode()
    expected=next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*')==IMAGE)
    source=root/IMAGE
    if not source.exists():
        urllib.request.urlretrieve(BASE+IMAGE,source)
    with source.open('rb') as stream:
        actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=expected:
        raise ValueError('Cloud image SHA256 mismatch')
    (root/'source.json').write_text(json.dumps(dict(url=BASE+IMAGE,sha256=actual),indent=2)+'\n')
    key=root/'lab_key'
    if not key.exists(): command(['ssh-keygen','-t','ed25519','-N','','-f',key])
    public=key.with_suffix('.pub').read_text().strip()
    user_data=f'''#cloud-config
hostname: advanced-cp-lab
users:
  - name: cpoperator
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - {public}
chpasswd:
  expire: false
  users:
    - name: cpoperator
      password: {LAB_PASSWORD}
      type: text
ssh_pwauth: true
package_update: true
packages: [open-vm-tools, python3, curl, jq]
write_files:
  - path: /etc/cp-advanced-lab
    permissions: '0644'
    content: disposable-advanced-lab
runcmd:
  - [sh, -c, 'touch /var/lib/cp-lab-bootstrap-ready']
'''
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='CIDATA')
    for name, data in [('user-data',user_data),('meta-data','instance-id: cp-advanced-lab\nlocal-hostname: advanced-cp-lab\n')]:
        payload=data.encode()
        iso.add_fp(io.BytesIO(payload),len(payload),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
    iso.write(str(root/'seed.iso'));iso.close()
    command([VMWARE/'vmware-vdiskmanager.exe','-r',source,'-t','0',root/'lab.vmdk'])
    command([VMWARE/'vmware-vdiskmanager.exe','-x','24GB',root/'lab.vmdk'])
    values={'.encoding':'UTF-8','config.version':'8','virtualHW.version':'19',
            'displayName':'CP Advanced Disposable Lab','guestOS':'ubuntu-64','firmware':'efi',
            'memsize':'4096','numvcpus':'2','scsi0.present':'TRUE','scsi0.virtualDev':'lsilogic',
            'scsi0:0.present':'TRUE','scsi0:0.fileName':'lab.vmdk','sata0.present':'TRUE',
            'sata0:0.present':'TRUE','sata0:0.deviceType':'cdrom-image','sata0:0.fileName':'seed.iso',
            'ethernet0.present':'TRUE','ethernet0.connectionType':'nat','ethernet0.virtualDev':'e1000',
            'ethernet0.addressType':'generated','sharedFolder.maxNum':'0',
            'isolation.tools.hgfs.disable':'TRUE','serial0.present':'TRUE','serial0.fileType':'file',
            'serial0.fileName':'serial.log','usb.present':'FALSE','sound.present':'FALSE'}
    (root/'lab.vmx').write_text(''.join(f'{key} = "{value}"\n' for key,value in values.items()))
    command([VMWARE/'vmrun.exe','start',root/'lab.vmx','nogui'])
    guest=Guest(root)
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        try:
            guest.run('/usr/bin/test','-f','/var/lib/cp-lab-bootstrap-ready')
            print('BOOTSTRAP_READY',root/'lab.vmx')
            return
        except (RuntimeError,subprocess.TimeoutExpired):
            time.sleep(5)
    raise TimeoutError('Bootstrap did not complete; inspect serial.log and cloud-init logs before continuing')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['build','upload','run','get'])
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--vmx',default='lab.vmx')
    parser.add_argument('--file')
    parser.add_argument('--destination')
    args=parser.parse_args()
    if args.action=='build':
        build(args.directory);return
    guest=Guest(args.directory,args.vmx)
    if args.action=='upload':
        archive(Path(__file__).resolve().parents[2],guest.root/'repo.tgz')
        guest.upload(guest.root/'repo.tgz','/tmp/lab-repo.tgz')
        guest.run('/bin/mkdir','-p','/opt/cp-linux-setup')
        guest.run('/bin/tar','-xzf','/tmp/lab-repo.tgz','-C','/opt/cp-linux-setup')
    elif args.action=='run':
        if not args.file: parser.error('--file required')
        guest.script(Path(args.file).read_text(encoding='utf-8-sig'))
    else:
        if not args.file or not args.destination: parser.error('--file and --destination required')
        guest.download(args.file,args.destination)


if __name__=='__main__':
    main()
