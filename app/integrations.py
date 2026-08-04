from __future__ import annotations
import hashlib,hmac,json,logging,smtplib,socket,ssl,subprocess,urllib.request
from email.message import EmailMessage
from typing import Any
from app.storage import get_integrations
logger=logging.getLogger('scout-easy.integrations')

def _post_json(url:str,payload:dict[str,Any],headers:dict[str,str]|None=None)->None:
    data=json.dumps(payload,ensure_ascii=False).encode()
    req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json',**(headers or {})},method='POST')
    with urllib.request.urlopen(req,timeout=10) as r:
        if r.status>=300: raise RuntimeError(f'HTTP {r.status}')

def notify_alert(alert:dict[str,Any])->None:
    text=f"[{alert['severity'].upper()}] SCOUT-EASY: {alert['title']}\n{alert['description']}"
    payload={'source':'scout-easy','event':'alert','alert':alert,'host':socket.gethostname()}
    for item in get_integrations():
        if not item['enabled']: continue
        kind,cfg=item['kind'],item['config']
        try:
            if kind=='telegram':
                token=cfg.get('bot_token','');chat=cfg.get('chat_id','')
                if token and chat:_post_json(f'https://api.telegram.org/bot{token}/sendMessage',{'chat_id':chat,'text':text})
            elif kind=='webhook':
                url=cfg.get('url','');headers=cfg.get('headers',{}) if isinstance(cfg.get('headers'),dict) else {}
                secret=cfg.get('hmac_secret','')
                if secret:
                    raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode();headers['X-SCOUT-Signature']='sha256='+hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
                if url:_post_json(url,payload,headers)
            elif kind=='smtp':
                msg=EmailMessage();msg['Subject']=f"SCOUT-EASY: {alert['title']}";msg['From']=cfg.get('from',cfg.get('username','scout-easy@localhost'));msg['To']=cfg.get('to','');msg.set_content(text)
                host=cfg.get('host','localhost');port=int(cfg.get('port',587));mode=cfg.get('security','starttls')
                if mode=='ssl': server=smtplib.SMTP_SSL(host,port,timeout=10,context=ssl.create_default_context())
                else: server=smtplib.SMTP(host,port,timeout=10)
                with server:
                    if mode=='starttls':server.starttls(context=ssl.create_default_context())
                    if cfg.get('username'):server.login(cfg['username'],cfg.get('password',''))
                    server.send_message(msg)
            elif kind=='zabbix':
                server=cfg.get('server','127.0.0.1');host=cfg.get('host',socket.gethostname());key=cfg.get('key','scout.alert')
                subprocess.run(['zabbix_sender','-z',server,'-s',host,'-k',key,'-o',json.dumps(alert,ensure_ascii=False)],timeout=10,check=False,capture_output=True)
            elif kind=='syslog':
                address=(cfg.get('host','127.0.0.1'),int(cfg.get('port',514)));sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.sendto(text.encode(),address);sock.close()
        except Exception:
            logger.exception('notification_failed kind=%s',kind)
