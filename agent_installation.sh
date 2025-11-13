#!/usr/bin/env bash
set -euo pipefail

# === PMYS Agent Kurulum Scripti (root olarak) ===
# Pardus 23 uyumlu

AGENT_DIR="/opt/pmys_agent"
VENV_DIR="$AGENT_DIR/venv"
SERVICE_NAME="pmys_agent.service"
ENV_FILE="/etc/default/pmys_agent"

# LDAP_SERVER="ldap://192.168.161.139"
# LDAP_USER_DN="cn=admin,dc=giys,dc=org"
# LDAP_PASSWORD="admin"
# LDAP_BASE_DN="dc=giys,dc=org"


LDAP_SERVER="ldap://192.168.11.89"
LDAP_USER_DN="cn=admin,dc=giys,dc=org"
LDAP_PASSWORD="admin"
LDAP_BASE_DN="dc=giys,dc=org"

info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  err "Bu script root olarak çalıştırılmalıdır."
fi

info "=== PMYS Agent kurulumu başlıyor ==="

# 1. Gerekli paketler
info "Sistem güncelleniyor ve gerekli paketler yükleniyor..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv python3-dev \
    sssd sssd-ldap libnss-sss libpam-sss ldap-utils \
    libldap2-dev libsasl2-dev build-essential sudo curl net-tools

# 2. Dizin yapısı
info "Agent dizini hazırlanıyor..."
mkdir -p "$AGENT_DIR"
chmod 750 "$AGENT_DIR"

# 3. Python ortamı
info "Python sanal ortam hazırlanıyor..."
if [ -d "$VENV_DIR" ]; then
  warn "Mevcut venv bulundu; yeniden oluşturulacak."
  rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel

if [ -f "$AGENT_DIR/requirements.txt" ]; then
  info "requirements.txt bulundu, bağımlılıklar yükleniyor..."
  "$VENV_DIR/bin/pip" install -r "$AGENT_DIR/requirements.txt"
else
  warn "requirements.txt bulunamadı — sadece temel ortam kuruldu."
fi

# 4. Ortam değişkenleri
info "Servis ortam dosyası oluşturuluyor: $ENV_FILE"
cat > "$ENV_FILE" <<EOF
LDAP_SERVER="$LDAP_SERVER"
LDAP_USER_DN="$LDAP_USER_DN"
LDAP_PASSWORD="$LDAP_PASSWORD"
LDAP_BASE_DN="$LDAP_BASE_DN"
AGENT_DIR="$AGENT_DIR"
VENV_DIR="$VENV_DIR"
EOF
chmod 600 "$ENV_FILE"

# 5. SSSD yapılandırması
info "SSSD yapılandırması oluşturuluyor..."
mkdir -p /etc/sssd

cat > /etc/sssd/sssd.conf <<SSSD
[sssd]
config_file_version = 2
services = nss, pam
domains = LDAP

[nss]
filter_users = root,named,avahi,haldaemon,dbus,radiusd,news,nscd
filter_groups =

[pam]

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
sudo_provider = ldap
enumerate = true
cache_credentials = false
ldap_schema = rfc2307
ldap_uri = ${LDAP_SERVER}
ldap_search_base = ${LDAP_BASE_DN}
ldap_user_search_base = ${LDAP_BASE_DN}
ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_group_search_base = ${LDAP_BASE_DN}
ldap_group_object_class = posixGroup
ldap_group_name = cn
ldap_id_use_start_tls = false
ldap_tls_reqcert = never
ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
ldap_default_bind_dn = ${LDAP_USER_DN}
ldap_default_authtok = ${LDAP_PASSWORD}
access_provider = ldap
ldap_access_filter = (objectClass=posixAccount)
min_id = 1
max_id = 0
ldap_user_uuid = entryUUID
ldap_user_shell = loginShell
ldap_user_home_directory = homeDirectory
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_group_gid_number = gidNumber
ldap_group_uuid = entryUUID
ldap_group_member = memberUid
use_fully_qualified_names = false
ldap_access_order = filter
debug_level=6
SSSD

chmod 600 /etc/sssd/sssd.conf
systemctl restart sssd || true

# 6. Systemd servis dosyası
info "Systemd servis dosyası oluşturuluyor..."
cat > /etc/systemd/system/$SERVICE_NAME <<SERVICE
[Unit]
Description=PMYS Agent (root)
After=network.target sssd.service
Wants=sssd.service

[Service]
Type=simple
User=root
WorkingDirectory=${AGENT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${AGENT_DIR}/main.py
Restart=always
RestartSec=5
LimitNOFILE=4096
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

chmod 644 /etc/systemd/system/$SERVICE_NAME

# 7. Servisi aktif et
info "Servis başlatılıyor..."
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

# 8. Özet
info "=== Kurulum tamamlandı ==="
echo
systemctl status "$SERVICE_NAME" --no-pager || true
echo
echo "Logları görmek için:"
echo "  journalctl -u $SERVICE_NAME -f"
echo
echo "LDAP test etmek için:"
echo "  ldapsearch -x -H ${LDAP_SERVER} -D \"${LDAP_USER_DN}\" -w ${LDAP_PASSWORD} -b \"${LDAP_BASE_DN}\""
echo
info "Her şey root olarak çalışıyor."
