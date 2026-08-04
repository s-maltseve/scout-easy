from __future__ import annotations
import subprocess
from typing import Any

PROTECTED_PREFIXES=('scout-easy','ssh','sshd','nginx','systemd-','dbus','networking','NetworkManager','firewalld','ufw','fail2ban')

def collect_services() -> dict[str,Any]:
    files=subprocess.run(['systemctl','list-unit-files','--type=service','--no-legend','--no-pager'],text=True,capture_output=True,timeout=15,check=False)
    units=subprocess.run(['systemctl','list-units','--type=service','--all','--no-legend','--no-pager','--plain'],text=True,capture_output=True,timeout=15,check=False)
    enabled={}
    for line in files.stdout.splitlines():
        p=line.split()
        if len(p)>=2 and p[0].endswith('.service'):enabled[p[0]]=p[1]
    active={}
    for line in units.stdout.splitlines():
        p=line.split(None,4)
        if len(p)>=4 and p[0].endswith('.service'):active[p[0]]={'load':p[1],'active':p[2],'sub':p[3],'description':p[4] if len(p)>4 else ''}
    names=sorted(set(enabled)|set(active))
    services=[]
    for unit in names:
        name=unit[:-8];a=active.get(unit,{})
        services.append({'unit':unit,'name':name,'enabled':enabled.get(unit,'unknown'),'active':a.get('active','inactive'),'sub':a.get('sub','dead'),'description':a.get('description',''),'protected':name.startswith(PROTECTED_PREFIXES)})
    services.sort(key=lambda x:(x['active']!='active',x['name']))
    return {'services':services}
