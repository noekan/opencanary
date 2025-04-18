import json
import smtplib
import time
from email.message import EmailMessage
from collections import defaultdict

# === CONFIGURATION ===
HONEYPOT_NAME         = "Telcomex"
LOG_PATH              = "/var/tmp/opencanary.log"

EMAIL_FROM            = "honeypot@telcomex.ch"
EMAIL_TO              = ["nkanzallah@telcomex-ics.ch"]
EMAIL_SUBJECT         = "OpenCanary Alert"
SMTP_HOST             = "smtpauth.x-secure.ch"
SMTP_PORT             = 587
SMTP_USER             = "honeypot@telcomex.ch"
SMTP_PASSWORD         = "zN1x2cXHxN9t"

ALERT_THRESHOLD       = 3     # Nombre de tentatives avant alerte
NOTIFICATION_COOLDOWN = 120   # En secondes

# Pour stocker l’état
attempts_counter = defaultdict(int)   # { "IP-logtype": count }
last_notified    = {}                 # { "IP-logtype": timestamp }

# === Helpers ===
def describe_logtype(code):
    return {
        1000: "Connexion Telnet",
        2000: "Connexion FTP",
        3000: "Requête HTTP (vue)",
        3001: "Connexion HTTP (tentative d'identification)",
        4000: "Connexion SSH",
        5000: "Connexion SMB",
        6000: "Port Scan",
        7000: "Connexion RDP",
        8000: "Requête NTP",
        9000: "Requête MySQL",
        10000: "Connexion VNC",
        11000: "Connexion TFTP",
    }.get(code, f"Type inconnu ({code})")

def in_cooldown(key):
    """Retourne True si on est toujours dans la période de cooldown."""
    last = last_notified.get(key)
    if last is None:
        return False
    return (time.time() - last) < NOTIFICATION_COOLDOWN

def send_email(log_line, log):
    src      = f"{log['src_host']}:{log['src_port']}"
    dst      = f"{log['dst_host']}:{log['dst_port']}"
    date     = log.get("local_time_adjusted") or log.get("local_time") or "Inconnue"
    data     = log.get("logdata", {})
    path     = data.get("PATH", "N/A")
    hostname = data.get("HOSTNAME", log.get("dst_host", "N/A"))
    ua       = data.get("USERAGENT", "N/A")
    user     = data.get("USERNAME", "N/A")
    pwd      = data.get("PASSWORD", "N/A")
    ltype    = log.get("logtype", -1)

    body = f"""
🚨 Nouvelle activité détectée sur le honeypot **{HONEYPOT_NAME}** !

📅 Date : {date}
📍 Source : {src}
🎯 Cible : {dst}
🧠 Type : {describe_logtype(ltype)}

🔎 Détails :
- Chemin      : {path}
- Hostname    : {hostname}
- User-Agent  : {ua}
- Username    : {user}
- Password    : {pwd}

📄 Log brut :
{log_line.strip()}
""".strip()

    msg = EmailMessage()
    msg["From"]    = EMAIL_FROM
    msg["To"]      = ", ".join(EMAIL_TO)
    msg["Subject"] = f"{EMAIL_SUBJECT} - {HONEYPOT_NAME}"
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.send_message(msg)
    print("📧 Notification envoyée.")

# === Boucle principale ===
def follow_log():
    with open(LOG_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                log = json.loads(line)
                src      = log.get("src_host")
                port     = log.get("src_port")
                ltype    = log.get("logtype", -1)
                data     = log.get("logdata", {})

                # Filtrage de base
                if not src or port in (None, -1) or not isinstance(data, dict):
                    continue

                # Pour FTP (2000) ou HTTP login (3001), ignorer si pas de creds
                if ltype in (2000, 3001):
                    if not data.get("USERNAME") or not data.get("PASSWORD"):
                        continue

                key = f"{src}-{ltype}"

                # Si on est en cooldown, on ignore totalement
                if in_cooldown(key):
                    continue

                # Incrément du compteur
                attempts_counter[key] += 1
                count = attempts_counter[key]
                print(f"⚠️ Tentative détectée [{key}] ({count}/{ALERT_THRESHOLD})")

                # Seuil atteint → alerte + reset compteur + marquer notif
                if count >= ALERT_THRESHOLD:
                    send_email(line, log)
                    attempts_counter[key] = 0
                    last_notified[key] = time.time()

            except Exception as e:
                print(f"❌ Erreur parsing : {e}")

if __name__ == "__main__":
    print(f"🚨 Canary Watcher ({HONEYPOT_NAME}) démarré…")
    follow_log()