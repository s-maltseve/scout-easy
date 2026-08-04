from __future__ import annotations
import subprocess
from typing import Any
import psutil

PROTECTED_PREFIXES=('scout-easy','ssh','sshd','nginx','systemd-','dbus','networking','NetworkManager','firewalld','ufw','fail2ban')

def _resources(unit: str) -> tuple[int, float, int]:
    show=subprocess.run(['systemctl','show',unit,'--property=MainPID,ActiveEnterTimestampMonotonic,NRestarts','--value'],text=True,capture_output=True,timeout=5,check=False)
    values=show.stdout.splitlines()
    try: pid=int(values[0] or 0)
    except (ValueError,IndexError): pid=0
    try: restarts=int(values[2] or 0)
    except (ValueError,IndexError): restarts=0
    cpu=ram=0.0
    if pid>0:
        try:
            proc=psutil.Process(pid)
            cpu=proc.cpu_percent(interval=0.0)
            ram=proc.memory_info().rss / 1024 / 1024
            for child in proc.children(recursive=True):
                try:
                    cpu += child.cpu_percent(interval=0.0)
                    ram += child.memory_info().rss / 1024 / 1024
                except (psutil.NoSuchProcess,psutil.AccessDenied): pass
        except (psutil.NoSuchProcess,psutil.AccessDenied): pass
    return pid, round(cpu,1), round(ram,1), restarts

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
        pid,cpu,ram,restarts=_resources(unit) if a.get('active')=='active' else (0,0.0,0.0,0)
        services.append({'unit':unit,'name':name,'enabled':enabled.get(unit,'unknown'),'active':a.get('active','inactive'),'sub':a.get('sub','dead'),'description':a.get('description',''),'protected':name.startswith(PROTECTED_PREFIXES),'pid':pid,'cpu_percent':cpu,'memory_mb':ram,'restarts':restarts})
    services.sort(key=lambda x:(x['active']!='active',-x['memory_mb'],x['name']))
    return {'services':services}
