from __future__ import annotations
import hashlib,os
from pathlib import Path
from typing import Any
from app.storage import upsert_alert,check_file
from app.integrations import notify_alert

MONITORED=['/etc/passwd','/etc/group','/etc/sudoers','/etc/ssh/sshd_config','/root/.ssh/authorized_keys','/etc/crontab']

def emit(fp:str,severity:str,title:str,description:str,evidence:dict[str,Any]|None=None)->None:
    alert={'fingerprint':fp,'severity':severity,'title':title,'description':description,'evidence':evidence or {}}
    if upsert_alert(fp,severity,title,description,evidence):notify_alert(alert)

def _integrity()->None:
    for raw in MONITORED:
        p=Path(raw)
        try:
            if p.exists() and p.is_file():
                data=p.read_bytes();digest=hashlib.sha256(data).hexdigest();mtime=p.stat().st_mtime
            else:digest=None;mtime=None
            changed,old=check_file(raw,digest,mtime)
            if changed:emit(f'file-change:{raw}','high','Изменён критичный системный файл',f'Зафиксировано изменение {raw}. Проверьте, было ли оно запланировано.',{'path':raw,'sha256':digest,'previous_sha256':old})
        except (OSError,PermissionError):pass

def evaluate(snapshot: dict[str,Any]) -> None:
    overview=snapshot.get('overview',{});traffic=snapshot.get('traffic',{}).get('current',{});network=snapshot.get('network',{});processes=snapshot.get('processes',{})
    failed=int(overview.get('auth_failures',0) or 0)
    if failed>=80:emit('ssh-failures-high','high','Аномально много ошибок SSH',f'За выбранный журнал обнаружено {failed} неудачных входов.',{'count':failed})
    elif failed>=30:emit('ssh-failures-warning','warning','Повышенная активность SSH',f'Обнаружено {failed} неудачных входов.',{'count':failed})
    tx=float(traffic.get('sent_per_second',0) or 0)
    if tx>50*1024*1024:emit('outbound-traffic-critical','critical','Критический исходящий трафик','Исходящий поток превышает 50 МБ/с. Возможна компрометация или атака.',{'tx_bps':tx})
    elif tx>10*1024*1024:emit('outbound-traffic-high','high','Аномальный исходящий трафик','Исходящий поток превышает 10 МБ/с.',{'tx_bps':tx})
    active=int(network.get('summary',{}).get('total',0) or 0)
    if active>1000:emit('connections-critical','critical','Слишком много сетевых соединений',f'Обнаружено {active} соединений.',{'connections':active})
    elif active>300:emit('connections-high','high','Повышенное число соединений',f'Обнаружено {active} соединений.',{'connections':active})
    for item in processes.get('suspicious',[])[:10]:
        name=str(item.get('name') or item.get('process') or 'unknown');emit(f'suspicious-process:{name}','warning','Подозрительный процесс',f'Коллектор отметил процесс {name} как подозрительный.',item)
    _integrity()
