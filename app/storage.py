from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv('SCOUT_DB_PATH', '/var/lib/scout-easy/scout-easy.db'))
_LOCK = threading.RLock()

SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS traffic_samples (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts INTEGER NOT NULL,
 rx_bps REAL NOT NULL,
 tx_bps REAL NOT NULL,
 connections INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_samples(ts);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts INTEGER NOT NULL,
 actor TEXT NOT NULL,
 source_ip TEXT,
 action TEXT NOT NULL,
 target TEXT,
 result TEXT NOT NULL,
 details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 fingerprint TEXT NOT NULL UNIQUE,
 severity TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 evidence TEXT,
 status TEXT NOT NULL DEFAULT 'new',
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 occurrences INTEGER NOT NULL DEFAULT 1,
 resolved_at INTEGER,
 resolved_by TEXT,
 resolution_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status,last_seen);
CREATE TABLE IF NOT EXISTS integrations (
 kind TEXT PRIMARY KEY,
 enabled INTEGER NOT NULL DEFAULT 0,
 config TEXT NOT NULL DEFAULT '{}',
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS file_baseline (
 path TEXT PRIMARY KEY,
 sha256 TEXT,
 mtime REAL,
 checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
 bucket INTEGER PRIMARY KEY,
 ssh_success INTEGER NOT NULL DEFAULT 0,
 ssh_failure INTEGER NOT NULL DEFAULT 0,
 alerts INTEGER NOT NULL DEFAULT 0,
 audit INTEGER NOT NULL DEFAULT 0
);
'''

def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with _LOCK, connect() as conn:
        conn.executescript(SCHEMA)
        conn.commit()
    try: os.chmod(DB_PATH, 0o600)
    except OSError: pass

def add_traffic(rx_bps: float, tx_bps: float, connections: int) -> None:
    now = int(time.time())
    with _LOCK, connect() as conn:
        conn.execute('INSERT INTO traffic_samples(ts,rx_bps,tx_bps,connections) VALUES(?,?,?,?)', (now, rx_bps, tx_bps, connections))
        conn.execute('DELETE FROM traffic_samples WHERE ts < ?', (now - 8 * 86400,))
        conn.commit()

def traffic_history(seconds: int = 3600, limit: int = 480) -> list[dict[str, Any]]:
    since = int(time.time()) - max(300, min(seconds, 7 * 86400))
    with connect() as conn:
        rows = conn.execute('SELECT ts,rx_bps,tx_bps,connections FROM traffic_samples WHERE ts>=? ORDER BY ts ASC', (since,)).fetchall()
    if len(rows) > limit:
        step = max(1, len(rows) // limit)
        rows = rows[::step]
    return [dict(r) for r in rows]

def audit(actor: str, source_ip: str, action: str, target: str = '', result: str = 'success', details: dict[str, Any] | None = None) -> None:
    now = int(time.time())
    with _LOCK, connect() as conn:
        conn.execute('INSERT INTO audit_events(ts,actor,source_ip,action,target,result,details) VALUES(?,?,?,?,?,?,?)', (now, actor, source_ip, action, target, result, json.dumps(details or {}, ensure_ascii=False)))
        bucket = now - now % 86400
        conn.execute('INSERT INTO activity(bucket,audit) VALUES(?,1) ON CONFLICT(bucket) DO UPDATE SET audit=audit+1', (bucket,))
        conn.commit()

def list_audit(limit: int = 300) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute('SELECT * FROM audit_events ORDER BY ts DESC LIMIT ?', (max(1, min(limit, 2000)),)).fetchall()
    out=[]
    for row in rows:
        item=dict(row)
        try: item['details']=json.loads(item.get('details') or '{}')
        except Exception: item['details']={}
        out.append(item)
    return out

def upsert_alert(fingerprint: str, severity: str, title: str, description: str, evidence: dict[str, Any] | None = None) -> bool:
    now = int(time.time())
    with _LOCK, connect() as conn:
        previous=conn.execute('SELECT last_seen,status FROM alerts WHERE fingerprint=?',(fingerprint,)).fetchone()
        conn.execute('''INSERT INTO alerts(fingerprint,severity,title,description,evidence,status,first_seen,last_seen,occurrences)
          VALUES(?,?,?,?,?,'new',?,?,1)
          ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,title=excluded.title,description=excluded.description,
          evidence=excluded.evidence,last_seen=excluded.last_seen,occurrences=alerts.occurrences+1,
          status=CASE WHEN alerts.status='resolved' THEN 'new' ELSE alerts.status END,resolved_at=NULL,resolved_by=NULL,resolution_note=NULL''',
          (fingerprint,severity,title,description,json.dumps(evidence or {},ensure_ascii=False),now,now))
        bucket = now - now % 86400
        conn.execute('INSERT INTO activity(bucket,alerts) VALUES(?,1) ON CONFLICT(bucket) DO UPDATE SET alerts=alerts+1', (bucket,))
        conn.commit()
        return previous is None or previous['status']=='resolved' or now-int(previous['last_seen'])>300

def check_file(path: str, sha256: str | None, mtime: float | None) -> tuple[bool,str|None]:
    now=int(time.time())
    with _LOCK, connect() as conn:
        old=conn.execute('SELECT sha256,mtime FROM file_baseline WHERE path=?',(path,)).fetchone()
        conn.execute('INSERT INTO file_baseline(path,sha256,mtime,checked_at) VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,mtime=excluded.mtime,checked_at=excluded.checked_at',(path,sha256,mtime,now))
        conn.commit()
    if old is None:return False,None
    changed=(old['sha256'] or '')!=(sha256 or '') or float(old['mtime'] or 0)!=float(mtime or 0)
    return changed,old['sha256']

def list_alerts(active_only: bool = False, limit: int = 300) -> list[dict[str, Any]]:
    query='SELECT * FROM alerts'
    args=[]
    if active_only: query += " WHERE status!='resolved'"
    query += ' ORDER BY CASE severity WHEN \'critical\' THEN 4 WHEN \'high\' THEN 3 WHEN \'warning\' THEN 2 ELSE 1 END DESC,last_seen DESC LIMIT ?'
    args.append(max(1,min(limit,2000)))
    with connect() as conn: rows=conn.execute(query,args).fetchall()
    out=[]
    for row in rows:
        item=dict(row)
        try:item['evidence']=json.loads(item.get('evidence') or '{}')
        except Exception:item['evidence']={}
        out.append(item)
    return out

def resolve_alert(alert_id: int, actor: str, note: str='') -> bool:
    now=int(time.time())
    with _LOCK, connect() as conn:
        cur=conn.execute("UPDATE alerts SET status='resolved',resolved_at=?,resolved_by=?,resolution_note=? WHERE id=?",(now,actor,note,alert_id))
        conn.commit(); return cur.rowcount>0

def record_auth_activity(success: int, failure: int) -> None:
    bucket=int(time.time()); bucket-=bucket%86400
    with _LOCK, connect() as conn:
        conn.execute('INSERT INTO activity(bucket,ssh_success,ssh_failure) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET ssh_success=?,ssh_failure=?',(bucket,success,failure,success,failure))
        conn.commit()

def activity_heatmap(days: int=120) -> list[dict[str,Any]]:
    since=int(time.time())-days*86400
    with connect() as conn: rows=conn.execute('SELECT * FROM activity WHERE bucket>=? ORDER BY bucket',(since,)).fetchall()
    return [dict(r) for r in rows]

def get_integrations() -> list[dict[str,Any]]:
    kinds=['telegram','smtp','webhook','zabbix','prometheus','syslog']
    with connect() as conn: rows={r['kind']:r for r in conn.execute('SELECT * FROM integrations').fetchall()}
    out=[]
    for kind in kinds:
        row=rows.get(kind)
        cfg={}
        if row:
            try: cfg=json.loads(row['config'])
            except Exception: cfg={}
        out.append({'kind':kind,'enabled':bool(row['enabled']) if row else False,'config':cfg})
    return out

def set_integration(kind: str, enabled: bool, config: dict[str,Any]) -> None:
    if kind not in {'telegram','smtp','webhook','zabbix','prometheus','syslog'}: raise ValueError('unsupported integration')
    with _LOCK, connect() as conn:
        conn.execute('INSERT INTO integrations(kind,enabled,config,updated_at) VALUES(?,?,?,?) ON CONFLICT(kind) DO UPDATE SET enabled=excluded.enabled,config=excluded.config,updated_at=excluded.updated_at',(kind,int(enabled),json.dumps(config,ensure_ascii=False),int(time.time())))
        conn.commit()
