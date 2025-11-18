# -*- coding: utf-8 -*-
"""
LAPS komut işçisi (agent).
- laps_command kuyruğunu dinler
- 'set_local_admin_password' eylemini uygular
- sonucu laps_secret_reports kuyruğuna bildirir
"""
import json, os, time, threading, subprocess, secrets, string
from datetime import datetime, timedelta, timezone

import pika

# ------------ OS helpers (Linux) ------------
def _run(cmd, input_text=None):
    return subprocess.run(
        cmd,
        input=(input_text.encode() if isinstance(input_text, str) else input_text),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False
    )

def ensure_user(username: str, shell: str = "/bin/bash"):
    # varsa shell'i güncelle, yoksa -m -s ile oluştur
    if _run(["id", "-u", username]).returncode != 0:
        r = _run(["useradd", "-m", "-s", shell, username])
        if r.returncode != 0:
            raise RuntimeError(f"useradd failed: {r.stdout.decode(errors='ignore')}")
    else:
        _run(["usermod", "-s", shell, username])

    # home dizinini garanti eder
    home = f"/home/{username}"
    if not os.path.isdir(home):
        # mkhomedir_helper yoksa kendin oluştur
        if _run(["which", "mkhomedir_helper"]).returncode == 0:
            _run(["mkhomedir_helper", username])
        else:
            os.makedirs(home, exist_ok=True)
            _run(["chown", "-R", f"{username}:{username}", home])

    # hesabı kilitten çıkar ve bitiş tarihini iptal eder
    _run(["passwd", "-u", username])
    _run(["chage", "-E", "-1", username])  # never expires

def set_password(username: str, password: str):
    # chpasswd: "user:pass\n"
    r = _run(["chpasswd"], input_text=f"{username}:{password}\n")
    if r.returncode != 0:
        raise RuntimeError(f"chpasswd failed: {r.stdout.decode(errors='ignore')}")
    _run(["passwd", "-u", username])

def set_password_age(username: str, rotation_days: int, enforce_max_age: bool):
    if enforce_max_age and rotation_days and rotation_days > 0:
        _run(["chage", "-M", str(rotation_days), username])

def rename_user(old: str, new: str) -> str:
    if not new or new == old:
        return old
    r = _run(["usermod", "-l", new, old])
    if r.returncode != 0:
        raise RuntimeError(f"usermod -l failed: {r.stdout.decode(errors='ignore')}")
    return new

def schedule_post_action(action: str, delay_min: int):
    def _do():
        if action == "reboot":
            _run(["/sbin/reboot"])
        elif action == "shutdown":
            _run(["/sbin/shutdown", "-h", "now"])
        elif action == "logoff":
            user = os.getenv("SUDO_USER") or os.getenv("USER") or ""
            if user:
                _run(["loginctl", "terminate-user", user])
    if action and action != "none":
        t = threading.Timer(max(0, int(delay_min or 0)) * 60, _do)
        t.daemon = True
        t.start()

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    pools, must = [], []
    if use_upper:  pools.append(string.ascii_uppercase); must.append(secrets.choice(string.ascii_uppercase))
    if use_lower:  pools.append(string.ascii_lowercase); must.append(secrets.choice(string.ascii_lowercase))
    if use_digits: pools.append(string.digits);         must.append(secrets.choice(string.digits))
    if use_symbols:
        syms = "!@#$%^&*()-_=+[]{}:,.?"
        pools.append(syms); must.append(secrets.choice(syms))
    if not pools:
        pools = [string.ascii_lowercase]; must = [secrets.choice(string.ascii_lowercase)]
    allchars = "".join(pools)
    pw = must[:]
    while len(pw) < max(1, int(length or 16)):
        pw.append(secrets.choice(allchars))
    for i in range(len(pw)-1, 0, -1):
        j = secrets.randbelow(i+1)
        pw[i], pw[j] = pw[j], pw[i]
    return "".join(pw)

# ------------ Worker ------------
class LapsWorker:
    def __init__(self, conn_params: pika.ConnectionParameters, agent_uuid: str):
        self.conn_params = conn_params
        self.agent_uuid = agent_uuid
        self.conn = None
        self.ch = None

        self.queue_cmd = "laps_command"
        self.queue_report = "laps_secret_reports"

    def start(self):
        self.conn = pika.BlockingConnection(self.conn_params)
        self.ch = self.conn.channel()
        self.ch.queue_declare(queue=self.queue_cmd, durable=True)
        self.ch.queue_declare(queue=self.queue_report, durable=True)
        self.ch.basic_qos(prefetch_count=1)
        self.ch.basic_consume(queue=self.queue_cmd, on_message_callback=self._on_message, auto_ack=False)
        print("[LAPS] listening on", self.queue_cmd)
        try:
            self.ch.start_consuming()
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.ch.stop_consuming()
            except Exception:
                pass
            if self.conn and self.conn.is_open:
                self.conn.close()

    # ---- MQ callback
    def _on_message(self, ch, method, props, body):
        started = time.time()
        try:
            payload = json.loads(body.decode() if isinstance(body, (bytes, bytearray)) else body)
        except Exception as e:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        action = payload.get("action")
        uuid = payload.get("uuid") or self.agent_uuid

        resp = {"uuid": uuid, "ok": False, "error": None}

        try:
            if action == "set_local_admin_password":
                resp.update(self._handle_set_password(payload))
                resp["ok"] = True
            else:
                raise ValueError(f"Unknown action: {action}")
        except Exception as e:
            resp["error"] = str(e)

        # raporla
        self.ch.basic_publish(
            exchange="",
            routing_key=self.queue_report,
            properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
            body=json.dumps(resp).encode()
        )

        print("[LAPS] report:", resp)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    # ---- core
    def _handle_set_password(self, p: dict) -> dict:
        """
        payload beklenen:
        {
          "action": "set_local_admin_password",
          "uuid": "<client uuid>",
          "account": "Administrator",
          "new_password": "<opsiyonel>",
          "expires_at": "2025-10-09T11:22:33Z",
          "post_auth": {"action":"none|reset|logoff|reboot|shutdown", "delay_minutes": 0},
          "rename": {"enabled": false, "new_name": ""},
          "policy": { # opsiyonel, agent'ta generate etmek için
             "length": 16, "use_upper": true, "use_lower": true, "use_digits": true, "use_symbols": true,
             "rotation_days": 30, "enforce_max_age": true
          }
        }
        """
        account = p.get("account") or "Administrator"

        # Parola belirleme: sunucu gönderdi ise onu kullan, yoksa policy'den üret
        new_password = p.get("new_password")
        pol = p.get("policy") or {}
        if not new_password:
            new_password = generate_password(
                length=int(pol.get("length", 16)),
                use_upper=bool(pol.get("use_upper", True)),
                use_lower=bool(pol.get("use_lower", True)),
                use_digits=bool(pol.get("use_digits", True)),
                use_symbols=bool(pol.get("use_symbols", True)),
            )

        # Kullanıcıyı hazırla ve parolayı uygula
        ensure_user(account)
        set_password(account, new_password)
        set_password_age(
            account,
            int(pol.get("rotation_days", 30)),
            bool(pol.get("enforce_max_age", True))
        )

        # Yeniden adlandırma
        rn = p.get("rename") or {}
        if rn.get("enabled") and rn.get("new_name"):
            account = rename_user(account, rn["new_name"])

        # Post-auth aksiyon
        pa = p.get("post_auth") or {}
        schedule_post_action((pa.get("action") or "none").lower(), int(pa.get("delay_minutes") or 0))

        # expires_at ajan tarafında da tekilleştirilebilir
        expires_at = p.get("expires_at")
        if not expires_at and pol.get("rotation_days"):
            try:
                expires_at = (datetime.now(timezone.utc) + timedelta(days=int(pol["rotation_days"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                expires_at = None

        return {
            "account": account,
            "password": new_password,
            "expires_at": expires_at
        }
