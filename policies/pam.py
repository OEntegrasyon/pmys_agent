###############################################################################################################################
###                                                                                                                         ###
###                                             CIS PAM GÜVENLİK AYARLARI                                                  ###
###                                                                                                                         ###
###############################################################################################################################

import subprocess
import os
import glob
import shutil
import re


from utils import run_command
from logger import logger


def get_installed_package_version(package_name: str):
    """Belirtilen paketin kurulu sürümünü döndürür."""
    try:
        success, output = run_command(["dpkg-query", "-s", package_name])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        lines = output.splitlines()
        status_line = next((l for l in lines if l.startswith("Status:")), None)
        version_line = next((l for l in lines if l.startswith("Version:")), None)

        if not status_line or "install ok installed" not in status_line:
            return None, f"{package_name} kurulu değil"
        if version_line:
            installed_version = version_line.split(":", 1)[1].strip()
            return installed_version, None
        return None, f"{package_name} sürümü alınamadı"
    except subprocess.CalledProcessError:
        return None, f"{package_name} paketi bulunamadı"


def version_compare(v1, v2):
    """
    Debian versiyonlarını kıyaslamak için dpkg --compare-versions kullan.
    Dönen değer:
      -1 -> v1 < v2
       0 -> v1 == v2
       1 -> v1 > v2
    """
    if subprocess.run(["dpkg", "--compare-versions", v1, "lt", v2]).returncode == 0:
        return -1
    elif subprocess.run(["dpkg", "--compare-versions", v1, "gt", v2]).returncode == 0:
        return 1
    else:
        return 0


def check_libpam_runtime():
    """
    CIS 5.3.1.1 - Ensure latest version of pam is installed
    Minimum sürüm: 1.5.2-6
    """
    package = "libpam-runtime"
    required_version = "1.5.2-6"

    installed_version, error = get_installed_package_version(package)
    if error:
        return False, error

    cmp = version_compare(installed_version, required_version)
    if cmp < 0:
        return False, f"{package} ({installed_version}) sürümü minimum gereksinimin ({required_version}) altında."
    return True, f"{package} ({installed_version}) minimum gereksinimi ({required_version}) karşılıyor."


def apply_libpam_runtime(username=None, param=None):

    """
    CIS 5.3.1.1 için uygulatma fonksiyonu.

    """
    try:
        status, message = check_libpam_runtime()
        if status:
            return True, f"Değişiklik gerekmedi: {message}"

        
        success, output = run_command(["apt-get", "update"])
        if not success:
            return False, f"apt-get update çalıştırılamadı: {output}"

        success, output = run_command(["apt-get", "install", "--only-upgrade", "-y", "libpam-runtime"])
        if not success:
            return False, f"install çalıştırılamadı: {output}"
        
        return True, "libpam-runtime paketi güncellendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS5.3.1.1][APPLY] {msg}")
        return False, f"libpam-runtime uygulama hatası: {msg}"



def check_libpam_modules():
    """
    CIS 5.3.1.2 - Ensure libpam-modules is installed
    Minimum sürüm: 1.5.2-6
    """
    package = "libpam-modules"
    required_version = "1.5.2-6"

    installed_version, error = get_installed_package_version(package)
    if error:
        return False, error

    cmp = version_compare(installed_version, required_version)
    if cmp < 0:
        return False, f"{package} ({installed_version}) sürümü minimum gereksinimin ({required_version}) altında."
    return True, f"{package} ({installed_version}) minimum gereksinimi ({required_version}) karşılıyor."


def apply_libpam_modules(username=None, param=None):
    """
    CIS 5.3.1.2 için uygulatma fonksiyonu.
    minimum sürümü içeride sabitler.
    """
    try:
        status, message = check_libpam_modules()
        if status:
            return True, f"Değişiklik gerekmedi: {message}"

    
        success, output = run_command(["apt-get", "update"])
        if not success:
            return False, f"apt-get update çalıştırılamadı: {output}"

        success, output = run_command(["apt-get", "install", "--only-upgrade", "-y", "libpam-modules"])
        if not success:
            return False, f"install çalıştırılamadı: {output}"

        return True, "libpam-modules paketi güncellendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS5.3.1.2][APPLY] {msg}")
        return False, f"libpam-modules uygulama hatası: {msg}"



def check_libpam_pwquality():
    """
    CIS 5.3.1.3 - Ensure libpam-pwquality is installed
    """
    package = "libpam-pwquality"
    try:
        success, output = run_command(["dpkg-query", "-s", package])
        if not success:
            return False, f"dpkg-query çalıştırılamadı: {output}"

        lines = output.splitlines()  # 'result.stdout' yerine output
        status_line = next((l for l in lines if l.startswith("Status:")), None)
        version_line = next((l for l in lines if l.startswith("Version:")), None)

        if not status_line or "install ok installed" not in status_line:
            return False, f"{package} kurulu değil."
        
        version = version_line.split(":", 1)[1].strip() if version_line else "bilinmiyor"
        return True, f"{package} kurulu. Versiyon: {version}"

    except subprocess.CalledProcessError:
        return False, f"{package} bulunamadı."


def apply_libpam_pwquality(username=None, param=None):
    """
    CIS 5.3.1.3 - Ensure libpam-pwquality is installed
    """
    try:
        status, message = check_libpam_pwquality()
        if status:
            return True, f"Değişiklik gerekmedi: {message}"

    
        success, output = run_command(["apt-get", "update"])
        if not success:
            return False, f"apt-get update çalıştırılamadı: {output}"

        success, output = run_command(["apt-get", "install", "-y", "libpam-pwquality"])
        if not success:
            return False, f"apt-get install çalıştırılamadı: {output}"

        return True, "libpam-pwquality başarıyla kuruldu."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.1.3][APPLY] {msg}")
        return False, f"libpam-pwquality uygulama hatası: {msg}"



def check_pam_unix_enabled():
    """
    5.3.2.1 - Ensure pam_unix module is enabled
    /etc/pam.d/common-* dosyalarında pam_unix.so satırının olup olmadığını kontrol eder
    """
    pam_files = [
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-session-noninteractive"
    ]

    missing_files = []
    missing_unix = []

    for f in pam_files:
        if not os.path.exists(f):
            missing_files.append(f)
            continue

        try:
            with open(f, "r") as fh:
                content = fh.read()
                if "pam_unix.so" not in content:
                    missing_unix.append(f)
        except Exception as e:
            return False, f"{f} okunamadı: {e}"

    if missing_files:
        return False, f"Şu PAM dosyaları eksik: {', '.join(missing_files)}"
    if missing_unix:
        return False, f"pam_unix.so şu dosyalarda bulunamadı: {', '.join(missing_unix)}"

    return True, "pam_unix.so tüm ilgili PAM dosyalarında etkin."


def apply_pam_unix_enabled(username=None, param=None):
    """
    5.3.2.1 - Ensure pam_unix module is enabled
    pam_unix etkin değilse pam-auth-update ile etkinleştirir
    """
    try:
        status, message = check_pam_unix_enabled()
        if status:
            return True, f"Değişiklik gerekmedi: {message}"

        

        success, output = run_command(["pam-auth-update", "--enable", "unix"])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"
            
        return True, "pam_unix modülü başarıyla etkinleştirildi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.2.1][APPLY] {msg}")
        return False, f"pam_unix etkinleştirme başarısız: {msg}"
    


def check_pam_faillock_enabled():
    """
    5.3.2.2 Ensure pam_faillock module is enabled
    pam_faillock modülünün etkin olup olmadığını kontrol eder.
    """
    try:
        # common-auth ve common-account içinde pam_faillock satırlarını ara
        result = subprocess.run(
            ["grep", "-P", r"\bpam_faillock\.so\b", "/etc/pam.d/common-auth", "/etc/pam.d/common-account"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode == 0 and "pam_faillock.so" in result.stdout:
            return True, "pam_faillock modülü etkin."
        else:
            return False, "pam_faillock modülü etkin değil."
    except Exception as e:
        return False, f"Kontrol sırasında hata oluştu: {e}"


def apply_pam_faillock(username=None, param=None):
    """
    5.3.2.2 Ensure pam_faillock module is enabled
    pam_faillock modülünü etkinleştirir.
    """
    try:
        is_enabled, message = check_pam_faillock_enabled()
        if is_enabled:
            return True, f"Değişiklik gerekmedi: {message}"

    
        # faillock profili oluştur
        faillock_conf = """Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail
"""
        with open("/usr/share/pam-configs/faillock", "w") as f:
            f.write(faillock_conf)

        # faillock_notify profili oluştur
        faillock_notify_conf = """Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so
"""
        with open("/usr/share/pam-configs/faillock_notify", "w") as f:
            f.write(faillock_notify_conf)

        # pam-auth-update ile profilleri etkinleştir

        success, output = run_command(["pam-auth-update", "--enable", "faillock"])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"

        success, output = run_command(["pam-auth-update", "--enable", "faillock_notify"])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"
        
        return True, "pam_faillock modülü etkinleştirildi."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.2.2][APPLY] {msg}")
        return False, f"Uygulama sırasında hata oluştu: {msg}"




def check_pam_pwquality():
    try:
        success, output = run_command(["grep", "-P", r"\bpam_pwquality\.so\b", "/etc/pam.d/common-password"])
        if not success:
            return False, f"grep -P çalıştırılamadı: {output}"
        if "pam_pwquality.so" in output:
            logger.info("[check_pam_pwquality] pam_pwquality.so modülü zaten etkin.")
            return True, "pam_pwquality.so modülü etkin."
        else:
            logger.warning("[check_pam_pwquality] pam_pwquality.so modülü etkin değil.")
            return False, "pam_pwquality.so modülü etkin değil."
    except Exception as e:
        logger.error(f"[check_pam_pwquality] Hata: {e}")
        return False, f"Hata: {e}"

        

def apply_pam_pwquality(username=None, param=None):
    """
    5.3.2.3 Ensure pam_pwquality module is enabled
    Apply pam_pwquality.so module via pam-auth-update.
    """
    try:
        is_enabled, msg = check_pam_pwquality()
        if is_enabled:
            return True, f"Değişiklik gerekmedi: {msg}"

    
        profile_path = "/usr/share/pam-configs/pwquality"
        if not os.path.exists(profile_path):
            profile_content = [
                "Name: Pwquality password strength checking",
                "Default: yes",
                "Priority: 1024",
                "Conflicts: cracklib",
                "Password-Type: Primary",
                "Password:",
                " requisite pam_pwquality.so retry=3"
            ]
            with open(profile_path, "w") as f:
                f.write("\n".join(profile_content) + "\n")

        success, output = run_command(["pam-auth-update", "--enable", "pwquality"])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"

        is_enabled, msg = check_pam_pwquality()
        if is_enabled:
            return True, "pam_pwquality.so modülü başarıyla etkinleştirildi."
        else:
            return False, "pam_pwquality.so modülü etkinleştirilemedi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.2.3 ][APPLY] {msg}")
        return False, f"Hata: {msg}"



PWHISTORY_PROFILE_PATH = "/usr/share/pam-configs/pwhistory"
PWHISTORY_PROFILE_NAME = "pwhistory"
PWHISTORY_LINE = "requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok"


def check_pwhistory_enabled():
    """
    CIS 5.3.2.4 - Ensure pam_pwhistory module is enabled
    /etc/pam.d/common-password içinde pam_pwhistory.so satırını arar.
    """

    success, output = run_command(["grep", "-E", r"pam_pwhistory\.so", "/etc/pam.d/common-password"])
    if not success:
        return False, f"grep çalıştırılamadı: {output}"

    for line in output.splitlines():
        if "pam_pwhistory.so" in line:
            remember_match = re.search(r"remember=\d+", line)
            enforce_for_root = "enforce_for_root" in line

            if remember_match and enforce_for_root:
                logger.info("[check_pwhistory_enabled] pam_pwhistory etkin (remember + enforce_for_root bulundu).")
                return True, "pam_pwhistory etkin."
            else:
                logger.warning("[check_pwhistory_enabled] pam_pwhistory bulundu ama parametreler eksik.")
                return False, "pam_pwhistory bulundu ama parametreler eksik."

    logger.info("[check_pwhistory_enabled] pam_pwhistory etkin değil.")
    return False, "pam_pwhistory etkin değil."


def apply_pwhistory(username=None, param=None):
    """
    CIS 5.3.2.4 - Ensure pam_pwhistory module is enabled
    """
    is_enabled, msg = check_pwhistory_enabled()
    if is_enabled:
        return True, f"Değişiklik gerekmedi: {msg}"

    try:
        # Profil dosyası yoksa oluştur
        if not os.path.exists(PWHISTORY_PROFILE_PATH):
            profile_content = "\n".join([
                "Name: pwhistory password history checking",
                "Default: yes",
                "Priority: 1024",
                "Password-Type: Primary",
                "Password:",
                f"  {PWHISTORY_LINE}"
            ])
            with open(PWHISTORY_PROFILE_PATH, "w") as f:
                f.write(profile_content + "\n")
            logger.info(f"[apply_pwhistory] Oluşturulan profil: {PWHISTORY_PROFILE_PATH}")

        # pam-auth-update ile etkinleştir
        success, output = run_command(["pam-auth-update", "--enable", PWHISTORY_PROFILE_NAME])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"

        # Tekrar kontrol et
        is_enabled, msg = check_pwhistory_enabled()
        if is_enabled:
            return True, "pam_pwhistory modülü başarıyla etkinleştirildi."
        else:
            return False, "pam_pwhistory modülü etkinleştirilemedi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.2.4][APPLY] {msg}")
        return False, msg




FAILLOCK_CONF = "/etc/security/faillock.conf"
DEFAULT_DENY = 5  # site policy default

def check_failed_attempts_lockout(expected_deny=DEFAULT_DENY):
    """
    5.3.3.1.1 Ensure password failed attempts lockout is configured 
    Parola hatalı giriş kilitleme ayarını kontrol eder.
    expected_deny: izin verilen maksimum hatalı giriş sayısı (ör: 5)
    """
    if not os.path.exists(FAILLOCK_CONF):
        return False, f"{FAILLOCK_CONF} bulunamadı."

    try:
        with open(FAILLOCK_CONF, "r") as f:
            lines = f.readlines()
    except Exception as e:
        return False, f"faillock.conf okunamadı: {e}"

    deny_value = None
    for line in lines:
        if line.strip().startswith("deny"):
            try:
                deny_value = int(line.split("=")[1].strip())
            except Exception:
                continue

    if deny_value is None:
        return False, "deny parametresi bulunamadı."
    elif deny_value > expected_deny:
        return False, f"deny={deny_value}, beklenen en fazla {expected_deny}."
    else:
        return True, f"deny={deny_value}, uyumlu."


def apply_failed_attempts_lockout(username=None, param=None):
    """
    5.3.3.1.1 Ensure password failed attempts lockout is configured 
    Parola hatalı giriş kilitleme ayarını uygular.
    param: {"deny": 5} gibi bir sözlük alır.
    """
    try:
        param = param or {}
        expected_deny = param.get("deny", DEFAULT_DENY)

        is_ok, msg = check_failed_attempts_lockout(expected_deny)
        if is_ok:
            return True, f"Ayar zaten doğru: {msg}"

    

        backup_path = FAILLOCK_CONF + ".bak"
        shutil.copy2(FAILLOCK_CONF, backup_path)

        new_lines = []
        deny_found = False
        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if line.strip().startswith("deny"):
                    new_lines.append(f"deny = {expected_deny}\n")
                    deny_found = True
                else:
                    new_lines.append(line)

        if not deny_found:
            new_lines.append(f"deny = {expected_deny}\n")

        with open(FAILLOCK_CONF, "w") as f:
            f.writelines(new_lines)

        pam_dir = "/usr/share/pam-configs"
        if os.path.exists(pam_dir):
            for root, dirs, files in os.walk(pam_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r") as f:
                        content = f.read()
                    if "pam_faillock.so" in content and "deny=" in content:
                        fixed = []
                        for line in content.splitlines():
                            if "pam_faillock.so" in line and "deny=" in line:
                                parts = [p for p in line.split() if not p.startswith("deny=")]
                                fixed.append(" ".join(parts))
                            else:
                                fixed.append(line)
                        with open(fpath, "w") as f:
                            f.write("\n".join(fixed))

        return True, f"{FAILLOCK_CONF} dosyasında deny = {expected_deny} olarak ayarlandı."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.1.1][APPLY] {msg}")
        return False, f"Hata: {msg}"



BACKUP_FILE = "/etc/security/faillock.conf.bak"

def check_unlock_time(param=None):
    """
    CIS 5.3.3.1.2 - Kontrol
    unlock_time >= 900 saniye (15 dk) veya 0 olmalı.
    """
    try:
        expected_minutes = int((param or {}).get("unlock_time", 15))
        expected_seconds = expected_minutes * 60

        if not os.path.exists(FAILLOCK_CONF):
            return False, f"{FAILLOCK_CONF} bulunamadı."

        with open(FAILLOCK_CONF, "r") as f:
            content = f.read()

        match = re.search(r'^\s*unlock_time\s*=\s*(\d+)', content, re.MULTILINE)
        if not match:
            return False, "unlock_time parametresi bulunamadı."

        current_value = int(match.group(1))
        if current_value == 0 or current_value >= 900:
            return True, f"unlock_time uygun: {current_value} saniye"
        else:
            return False, f"unlock_time uygunsuz: {current_value} saniye (>=900 veya 0 olmalı)"
    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_unlock_time(username=None, param=None):
    """
    CIS 5.3.3.1.2 - Uygulama
    unlock_time >= 900 saniye olacak şekilde ayarlar.
    Eğer parametrede daha düşük verilirse bile 900 yapılır.
    """
    try:
        param = param or {}
        expected_minutes = int(param.get("unlock_time", 15))
        expected_seconds = max(expected_minutes * 60, 900)  # CIS minimum enforce

        ok, msg = check_unlock_time(param)
        if ok:
            return True, f"Zaten uygun: {msg}"

        shutil.copy2(FAILLOCK_CONF, BACKUP_FILE)

        updated_lines = []
        found = False
        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if line.strip().startswith("unlock_time"):
                    updated_lines.append(f"unlock_time = {expected_seconds}\n")
                    found = True
                else:
                    updated_lines.append(line)

        if not found:
            updated_lines.append(f"\nunlock_time = {expected_seconds}\n")

        with open(FAILLOCK_CONF, "w") as f:
            f.writelines(updated_lines)

        return True, f"unlock_time {expected_seconds} saniye ({expected_seconds//60} dakika) olarak ayarlandı."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.1.2][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_root_account_lock(param):
    """
    CIS 5.3.3.1.3 - Ensure password failed attempts lockout includes root account
    Parametre:
        param: {
            "root_unlock_time": int (saniye cinsinden, min 60)
        }
    """

    required_unlock_time = int(param.get("root_unlock_time", 60))

    if not os.path.exists(FAILLOCK_CONF):
        return False, f"{FAILLOCK_CONF} bulunamadı."

    with open(FAILLOCK_CONF, "r") as f:
        lines = f.readlines()

    has_even_deny_root = any("even_deny_root" in line.strip() and not line.strip().startswith("#") for line in lines)

    unlock_time_value = None
    for line in lines:
        if line.strip().startswith("root_unlock_time"):
            try:
                unlock_time_value = int(line.split("=")[1].strip())
            except Exception:
                return False, "root_unlock_time satırı hatalı biçimde yazılmış."
    if unlock_time_value == 0:
        return False, "root_unlock_time = 0 olmamalıdır (DoS riski)."

    if not has_even_deny_root:
        return False, "even_deny_root ayarı eksik."

    if unlock_time_value is None or unlock_time_value < required_unlock_time:
        return False, f"root_unlock_time {required_unlock_time} saniyeden küçük veya tanımsız."

    return True, f"Root hesap kilitleme ayarları uygun. (root_unlock_time={unlock_time_value}, even_deny_root etkin)"


def apply_root_account_lock(username=None, param=None):
    """
    CIS 5.3.3.1.3 için uygulatma fonksiyonu.
    """
    try:
        status, message = check_root_account_lock(param)
        if status:
            return True, f"Değişiklik gerekmedi: {message}"

        required_unlock_time = int(param.get("root_unlock_time", 60))

        backup_path = FAILLOCK_CONF + ".bak"
        shutil.copy2(FAILLOCK_CONF, backup_path)

        new_lines = []
        updated_even_deny_root = False
        updated_unlock_time = False

        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if line.strip().startswith("even_deny_root"):
                    new_lines.append("even_deny_root\n")
                    updated_even_deny_root = True
                elif line.strip().startswith("root_unlock_time"):
                    new_lines.append(f"root_unlock_time = {required_unlock_time}\n")
                    updated_unlock_time = True
                else:
                    new_lines.append(line)

        if not updated_even_deny_root:
            new_lines.append("even_deny_root\n")
        if not updated_unlock_time:
            new_lines.append(f"root_unlock_time = {required_unlock_time}\n")

        with open(FAILLOCK_CONF, "w") as f:
            f.writelines(new_lines)

        # PAM configte varsa hatalı root_unlock_time satırlarını kaldır
        pam_files = subprocess.getoutput("grep -Pl -- '\\bpam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?root_unlock_time' /usr/share/pam-configs/*")
        if pam_files:
            for file in pam_files.splitlines():
                with open(file, "r") as f:
                    lines = f.readlines()
                new_lines = [line for line in lines if "root_unlock_time" not in line]
                with open(file, "w") as f:
                    f.writelines(new_lines)

            success, output = run_command(["pam-auth-update"])
            if not success:
                return False, f"pam-auth-update çalıştırılamadı: {output}"

        return True, f"{FAILLOCK_CONF} güncellendi. Root başarısız giriş kilitleme etkin (root_unlock_time={required_unlock_time})."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.1.3][APPLY] {msg}")  
        return False, f"Hata: {msg}"



PWQUALITY_CONF = "/etc/security/pwquality.conf"
PWQUALITY_CONF_DIR = "/etc/security/pwquality.conf.d/"
PWQUALITY_CONF_FILE = f"{PWQUALITY_CONF_DIR}50-pwdifok.conf"
PAM_CONFIG_DIR = "/usr/share/pam-configs/"

def check_pwquality_difok(difok_min=2):
    """
    pwquality.conf ve pwquality.conf.d içindeki difok ayarını kontrol eder.
    """
    try:
        config_files = [PWQUALITY_CONF]

        if os.path.isdir(PWQUALITY_CONF_DIR):
            for f in os.listdir(PWQUALITY_CONF_DIR):
                full_path = os.path.join(PWQUALITY_CONF_DIR, f)
                if os.path.isfile(full_path) and f.endswith(".conf"):
                    config_files.append(full_path)

        found_value = None
        success, output = run_command([
            "grep", "-Psi", r"^\s*difok\s*=\s*[0-9]+", *config_files
        ])

        if success and output:
            for line in output.splitlines():
                try:
                    value = int(line.strip().split("=")[-1])
                    if value >= difok_min:
                        logger.info(f"[check_pwquality_difok] Uygun difok bulundu: {value}")
                        return True
                except ValueError:
                    continue

        logger.warning("[check_pwquality_difok] Uygun difok değeri bulunamadı.")
        return False
    except Exception as e:
        logger.error(f"[check_pwquality_difok] Hata: {e}")
        return False



def apply_pwquality_difok(username=None, param=None):
    """
    CIS 5.3.3.2.1 - Ensure password number of changed characters is configured
    """
    try:
        difok = 2
        if isinstance(param, dict):
            difok = int(param.get("difok", 2))
        elif param is not None:
            difok = int(param)

        if check_pwquality_difok(difok):
            return True, f"difok zaten {difok} veya üstünde."

        run_command(["sed", "-ri", r"s/^\s*difok\s*=/# &/", PWQUALITY_CONF])
        run_command(["mkdir", "-p", PWQUALITY_CONF_DIR])
        cmd_write = ["bash", "-c", f"printf '\\ndifok = {difok}\\n' > {PWQUALITY_CONF_FILE}"]
        success, output = run_command(cmd_write)

        if not success:
            return False, f"Difok değeri yazılamadı: {output}"

        # PAM configlerden difok temizle
        cmd_find_pam = ["grep", "-Pl", r"\bpam_pwquality\.so\b.*difok\b", f"{PAM_CONFIG_DIR}*"]
        success, output = run_command(cmd_find_pam)
        if success and output:
            for file in output.splitlines():
                run_command(["sed", "-ri", r"s/\bdifok\s*=\s*\d+\b//g", file])
                logger.info(f"[apply_pwquality_difok] {file} içindeki difok parametresi temizlendi.")

        return True, f"Difok {difok} olarak ayarlandı."

    except Exception as e:
        msg = f"Hata: {str(e)}" 
        logger.error(f"[CIS 5.3.3.2.1 ][APPLY] {msg}") 
        return False, f"Hata: {msg}"



PWQUALITY_FILE = os.path.join(PWQUALITY_CONF_DIR, "50-pwlength.conf")
CIS_MINLEN = 14  # CIS önerilen minimum

def check_min_password_length(param=None):
    """
    CIS 5.3.3.2.2 - Ensure minimum password length is configured
    """
    try:
        minlen = CIS_MINLEN
        if param and "minlen" in param:
            minlen = max(CIS_MINLEN, int(param["minlen"]))

        logger.info(f"[check_min_password_length] Kontrol ediliyor, minlen >= {minlen}")

        success, output = run_command([
            "grep", "-Psi",
            rf"^\h*minlen\h*=\h*({minlen}|[1-9][0-9]+)\b",
            PWQUALITY_CONF,
            os.path.join(PWQUALITY_CONF_DIR, "*.conf")
        ])
        if success and output:
            return True, f"Mevcut minlen değeri {minlen} veya üstünde."
        else:
            return False, f"Mevcut minlen değeri {minlen} altında."
    except Exception as e:
        return False, f"Hata: {e}"


def apply_min_password_length(username=None, param=None):
    """
    CIS 5.3.3.2.2 - Ensure minimum password length is configured
    """
    try:
        minlen = CIS_MINLEN
        if param and "minlen" in param:
            minlen = max(CIS_MINLEN, int(param["minlen"]))

        ok, msg = check_min_password_length({"minlen": minlen})
        if ok:
            return True, f"Zaten uygun: {msg}"

        # eski değerleri kapat
        run_command(["sed", "-ri", r"s/^\s*minlen\s*=/# &/", PWQUALITY_CONF])

        if not os.path.isdir(PWQUALITY_CONF_DIR):
            os.makedirs(PWQUALITY_CONF_DIR)

        with open(PWQUALITY_FILE, "w") as f:
            f.write(f"minlen = {minlen}\n")

        success, output = run_command([
            "grep", "-Pl",
            r"\bpam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\b",
            "/usr/share/pam-configs/*"
        ])
        if success and output:
            for file in output.splitlines():
                run_command(["sed", "-ri", r"s/\bminlen\s*=\s*\d+\b//g", file])
                logger.info(f"[apply_min_password_length] PAM modülünden minlen parametresi temizlendi: {file}")

        return True, f"minlen {minlen} olarak ayarlandı."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.2 ][APPLY] {msg}")
        return False, f"Hata: {msg}"



PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwcomplexity.conf"

def check_pw_complexity(param: dict) -> (bool, str):
    """
    CIS 5.3.3.2.3 - Ensure password complexity is configured
    Kontrol edilen parametreler: minclass, dcredit, ucredit, lcredit, ocredit
    """
    conf_files = [PWQUALITY_CONF]

    if os.path.isdir("/etc/security/pwquality.conf.d/"):
        for f in os.listdir("/etc/security/pwquality.conf.d/"):
            if f.endswith(".conf"):
                conf_files.append(os.path.join("/etc/security/pwquality.conf.d/", f))

    content = ""
    for file in conf_files:
        try:
            with open(file, "r") as f:
                content += f.read() + "\n"
        except Exception as e:
            logger.error(f"[check_pw_complexity] Dosya okunamadı: {file}, Hata: {str(e)}")

    # Parametrelere göre kontrol yap
    for key, expected_value in param.items():
        match = re.search(rf'^\s*{key}\s*=\s*(-?\d+)', content, re.MULTILINE)
        if not match or int(match.group(1)) != int(expected_value):
            return False, f"{key} için beklenen {expected_value}, mevcut: {match.group(1) if match else 'yok'}"

    return True, "Tüm parola karmaşıklık parametreleri uyumlu."


def apply_pw_complexity(username=None, param=None):
    """
    CIS 5.3.3.2.3 - Ensure password complexity is configured
    Param örnek: {"minclass": 3, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1}
    """
    try:
        param = param or {"minclass": 3, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1}

        is_ok, msg = check_pw_complexity(param)
        if is_ok:
            return True, f"Ayar zaten uyumlu. {msg}"

        # 1. pwquality.conf içindeki eski satırları yorumla
        run_command(["sed", "-ri", r's/^\s*(minclass|[dulo]credit)\s*=/# &/', PWQUALITY_CONF])

        # 2. pwquality.conf.d klasörü yoksa oluştur
        if not os.path.isdir("/etc/security/pwquality.conf.d/"):
            os.makedirs("/etc/security/pwquality.conf.d/")

        # 3. yeni parametreleri .d dosyasına yaz
        lines = []
        for key in ["minclass", "dcredit", "ucredit", "lcredit", "ocredit"]:
            lines.append(f"{key} = {param.get(key, -1) if key != 'minclass' else param.get('minclass', 3)}")
        with open(PWQUALITY_CONF_D, "w") as f:
            f.write("\n".join(lines) + "\n")

        # 4. PAM modüllerinden eski parametreleri temizle
        cmd_find_pam = ["grep", "-Pl", r"\bpam_pwquality\.so\b.*(minclass|[dulo]credit)", f"{PAM_CONFIG_DIR}*"]
        success, output = run_command(cmd_find_pam)
        if success and output:
            files = output.splitlines()
            for file in files:
                run_command(["sed", "-ri", r's/\b(minclass|[dulo]credit)\s*=\s*-?\d+\b//g', file])
                logger.info(f"[apply_pw_complexity] {file} içindeki eski parametreler temizlendi.")

        return True, f"Parola karmaşıklık parametreleri uygulandı: {param}"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.3][APPLY] {msg}")
        return False, msg



PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwrepeat.conf"
COMMON_PASSWORD = "/etc/pam.d/common-password"

def check_maxrepeat(expected_value=3):
    """
    CIS 5.3.3.2.4 - Ensure password same consecutive characters is configured
    Beklenen: maxrepeat 1–expected_value arasında olmalı (0 kabul edilmez).
    """
    logger.info("[check_maxrepeat] Parola maxrepeat ayarları kontrol ediliyor...")

    current_value = None

    conf_files = [PWQUALITY_CONF]
    if os.path.isdir("/etc/security/pwquality.conf.d/"):
        for f in os.listdir("/etc/security/pwquality.conf.d/"):
            if f.endswith(".conf"):
                conf_files.append(os.path.join("/etc/security/pwquality.conf.d/", f))

    for file in conf_files:
        try:
            with open(file, "r") as f:
                for line in f:
                    if line.strip().startswith("maxrepeat"):
                        try:
                            current_value = int(line.split("=")[1].strip())
                            break
                        except Exception:
                            continue
        except FileNotFoundError:
            continue

    try:
        with open(COMMON_PASSWORD, "r") as f:
            for line in f:
                if "pam_pwquality.so" in line and "maxrepeat" in line:
                    logger.warning("[check_maxrepeat] /etc/pam.d/common-password içinde maxrepeat override edilmiş!")
                    return False, f"Override bulundu: {line.strip()}"
    except FileNotFoundError:
        logger.warning(f"[check_maxrepeat] {COMMON_PASSWORD} bulunamadı.")

    if current_value is None:
        current_value = 0

    logger.info(f"[check_maxrepeat] Mevcut maxrepeat = {current_value}, Beklenen: 1–{expected_value}")

    if 1 <= current_value <= expected_value:
        return True, f"maxrepeat uygun: {current_value}"
    else:
        return False, f"maxrepeat uyumsuz: {current_value}"


def apply_maxrepeat(username=None, param=None):
    """
    CIS 5.3.3.2.4 uyumlu hale getir.
    Param örnek: {"maxrepeat": 3}
    """
    try:
        desired_value = int(param.get("maxrepeat", 3)) if param else 3

        logger.info(f"[apply_maxrepeat] maxrepeat {desired_value} olarak uygulanacak.")

        is_ok, msg = check_maxrepeat(expected_value=desired_value)
        if is_ok:
            logger.info(f"[apply_maxrepeat] Zaten uyumlu: {msg}")
            return True, msg

        # pwquality.conf içindeki eski satırları yorumla
        run_command(["sed", "-ri", r"s/^\s*maxrepeat\s*=/# &/", PWQUALITY_CONF])


        if not os.path.isdir(os.path.dirname(PWQUALITY_CONF_D)):
            os.makedirs(os.path.dirname(PWQUALITY_CONF_D), exist_ok=True)

        try:
            with open(PWQUALITY_CONF_D, "w") as f:
                f.write(f"maxrepeat = {desired_value}\n")
            logger.info(f"[apply_maxrepeat] {PWQUALITY_CONF_D} dosyasına maxrepeat = {desired_value} yazıldı.")
        except Exception as e:
            logger.error(f"[apply_maxrepeat] Dosya yazma hatası: {e}")
            return False, str(e)

        return check_maxrepeat(expected_value=desired_value)

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.4 ][APPLY] {msg}")
        return False, f"Hata: {msg}"



    
def check_maxsequence(expected_value=3):
    """
    maxsequence değerini kontrol et.
    CIS uyumu için değer 1-3 arası olmalı ve 0 olmamalı.
    """
    config_files = ["/etc/security/pwquality.conf"]

    # /etc/security/pwquality.conf.d içindeki dosyaları ekle
    conf_d_path = "/etc/security/pwquality.conf.d"
    if os.path.isdir(conf_d_path):
        for f in os.listdir(conf_d_path):
            full_path = os.path.join(conf_d_path, f)
            if os.path.isfile(full_path):
                config_files.append(full_path)

    found_value = None
    success, output = run_command([
        "grep", "-Psi", r'^\s*maxsequence\s*=\s*\d+', *config_files
    ])

    if success and output:
        match = re.search(r"maxsequence\s*=\s*(\d+)", output)
        if match:
            found_value = int(match.group(1))

    if found_value is None:
        logger.warning("[check_maxsequence] maxsequence ayarı bulunamadı.")
        return False, "maxsequence ayarı bulunamadı"

    if found_value == 0:
        return False, f"maxsequence={found_value}, 0 olmamalı"
    if found_value > 3:
        return False, f"maxsequence={found_value}, 3 veya daha az olmalı"

    if found_value != expected_value:
        return False, f"maxsequence={found_value}, beklenen={expected_value}"

    return True, f"maxsequence={found_value}, uyumlu"



def apply_maxsequence(username=None, param=None):
    """
    5.3.3.2.5 Ensure password maximum sequential characters is configured.
    maxsequence değerini uygula. CIS'e uygun şekilde yapılandırır.
    Önce mevcut durumu check eder, uyumlu değilse düzeltir.

    Args:
        param (dict): {"value": 3} şeklinde beklenen parametre

    Returns:
        (bool, str): (Başarılı mı?, Mesaj)
    """
    expected_value = param.get("value", 3) if param else 3

    compliant, message = check_maxsequence(expected_value)
    if compliant:
        logger.info(f"[apply_maxsequence] Uyumlu, işlem yapılmadı. ({message})")
        return True, message

    logger.info(f"[apply_maxsequence] Uyumlu değil: {message} → Düzeltiliyor...")

    # Eski ayarı yorum satırına al
    run_command([
        "sed", "-ri", r's/^\s*maxsequence\s*=/# &/',
        "/etc/security/pwquality.conf"
    ])

    if not os.path.exists("/etc/security/pwquality.conf.d"):
        os.makedirs("/etc/security/pwquality.conf.d")

    conf_file = "/etc/security/pwquality.conf.d/50-pwmaxsequence.conf"
    try:
        with open(conf_file, "w") as f:
            f.write(f"maxsequence = {expected_value}\n")
        logger.info(f"[apply_maxsequence] maxsequence={expected_value} olarak ayarlandı ({conf_file})")
        return True, f"maxsequence {expected_value} olarak ayarlandı"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_maxsequence] Yazma hatası: {msg}")
        return False, f"maxsequence ayarlanamadı: {msg}"



def check_dictcheck(expected_value=1):
    """
    5.3.3.2.6 Ensure password dictionary check is enabled
    dictcheck değerini kontrol et.
    CIS uyumu için dictcheck 0 olmamalı.

    Returns:
        (bool, str): (Uyumlu mu?, Mesaj)
    """
    config_files = [
        "/etc/security/pwquality.conf",
        "/etc/security/pwquality.conf.d/*.conf"
    ]

    # 1) pwquality.conf ve .d altındaki dosyalarda dictcheck=0 arama
    success, output = run_command([
        "grep", "-Psi", r'^\h*dictcheck\h*=\h*0\b', *config_files
    ])
    if success and output:
        return False, f"dictcheck=0 bulundu (pwquality.conf veya .d altında)."

    # 2) PAM dosyalarında dictcheck=0 parametresi arama
    success, output = run_command([
        "grep", "-Psi", r'^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so.*dictcheck\h*=\h*0\b',
        "/etc/pam.d/common-password"
    ])
    if success and output:
        return False, "pam_pwquality satırında dictcheck=0 bulundu!"

    # 3) Hiçbir yerde 0 yok → uyumlu
    return True, f"dictcheck etkin (varsayılan={expected_value})"


def apply_dictcheck(username=None, param=None):
    """
    5.3.3.2.6 Ensure password dictionary check is enabled
    CIS'e uygun şekilde dictcheck=1 olacak şekilde yapılandırır.
    Önce mevcut durumu check eder, uyumlu değilse düzeltir.

    Args:
        param (dict): {"value": 1} şeklinde beklenen parametre

    Returns:
        (bool, str): (Başarılı mı?, Mesaj)
    """
    expected_value = param.get("value", 1) if param else 1

    compliant, message = check_dictcheck(expected_value)
    if compliant:
        logger.info(f"[apply_dictcheck] Uyumlu, işlem yapılmadı. ({message})")
        return True, message

    logger.info(f"[apply_dictcheck] Uyumlu değil: {message} → Düzeltiliyor...")

    # 1) pwquality.conf ve .d içindekileri temizle (dictcheck=0 varsa yorum satırına al)
    run_command([
        "sed", "-ri", r's/^\s*dictcheck\s*=\s*0\b/# &/',
        "/etc/security/pwquality.conf"
    ])
    run_command([
        "sed", "-ri", r's/^\s*dictcheck\s*=\s*0\b/# &/',
        "/etc/security/pwquality.conf.d/" + "*.conf"
    ])

    # 2) pam_pwquality satırlarından dictcheck=0 argümanını kaldır
    run_command([
        "sed", "-ri", r's/\bdictcheck\s*=\s*0\b//g',
        "/etc/pam.d/common-password"
    ])

    if not os.path.exists("/etc/security/pwquality.conf.d"):
        os.makedirs("/etc/security/pwquality.conf.d")

    conf_file = "/etc/security/pwquality.conf.d/50-dictcheck.conf"
    try:
        with open(conf_file, "w") as f:
            f.write(f"dictcheck = {expected_value}\n")
        logger.info(f"[apply_dictcheck] dictcheck={expected_value} olarak ayarlandı ({conf_file})")
    except Exception as e:
        logger.error(f"[apply_dictcheck] Yazma hatası: {e}")
        return False, f"dictcheck ayarlanamadı: {e}"


    final_ok, final_msg = check_dictcheck(expected_value)
    return final_ok, final_msg





def check_enforcing(expected_value=1):
    """
    CIS 5.3.3.2.7 - Ensure password quality checking is enforced
    Check pwquality.conf and PAM common-password for enforcing=0
    """
    try:
        # 1. pwquality.conf dosyalarını kontrol et
        config_files = ["/etc/security/pwquality.conf"] + glob.glob("/etc/security/pwquality.conf.d/*.conf")
        for conf_file in config_files:
            if not os.path.exists(conf_file):
                continue
            with open(conf_file, "r") as f:
                for line in f:
                    line_clean = line.strip().lower()
                    if line_clean.startswith("enforcing") and line_clean.endswith("0"):
                        return False, f"{conf_file} içinde enforcing=0 bulundu!"

        # 2. PAM satırlarını kontrol et
        if os.path.exists(COMMON_PASSWORD):
            with open(COMMON_PASSWORD, "r") as f:
                for line in f:
                    line_clean = line.strip()
                    if "pam_pwquality.so" in line_clean and "enforcing=0" in line_clean:
                        return False, f"{COMMON_PASSWORD} içinde pam_pwquality.so enforcing=0 bulundu!"

        return True, f"enforcing={expected_value} (uyumlu)"

    except Exception as e:
        return False, f"Hata: {e}"


def apply_enforcing(username=None, param=None):
    """
    CIS 5.3.3.2.7 - Ensure password quality checking is enforced
    Düzeltme:
    - pwquality.conf dosyalarında enforcing=0 satırlarını yorumla
    - PAM common-password içindeki pam_pwquality.so satırına enforcing=1 ekle
    """
    try:
        expected_value = "1"
        compliant, message = check_enforcing(expected_value)
        if compliant:
            logger.info(f"[apply_enforcing] Zaten uyumlu: {message}")
            return True, message

        logger.info(f"[apply_enforcing] Uyumlu değil: {message} → Düzeltiliyor...")

        # 1. pwquality.conf ve conf.d/*.conf
        config_files = ["/etc/security/pwquality.conf"] + glob.glob("/etc/security/pwquality.conf.d/*.conf")
        for conf_file in config_files:
            if not os.path.exists(conf_file):
                continue
            with open(conf_file, "r") as f:
                lines = f.readlines()
            new_lines = []
            for line in lines:
                if line.strip().lower().startswith("enforcing") and line.strip().endswith("0"):
                    new_lines.append("# " + line)
                else:
                    new_lines.append(line)
            with open(conf_file, "w") as f:
                f.writelines(new_lines)

        if os.path.exists(COMMON_PASSWORD):
            with open(COMMON_PASSWORD, "r") as f:
                lines = f.readlines()
            new_lines = []
            for line in lines:
                if "pam_pwquality.so" in line:
                    # enforcing parametresi varsa sil ve ekle
                    parts = line.strip().split()
                    parts = [p for p in parts if not p.startswith("enforcing=")]
                    parts.append(f"enforcing={expected_value}")
                    new_lines.append(" ".join(parts) + "\n")
                else:
                    new_lines.append(line)
            with open(COMMON_PASSWORD, "w") as f:
                f.writelines(new_lines)

        # 3. Eğer conf.d dizini yoksa oluştur
        if not os.path.exists("/etc/security/pwquality.conf.d"):
            os.makedirs("/etc/security/pwquality.conf.d")

        # 4. Yeni enforcing.conf dosyası ekle
        conf_file = "/etc/security/pwquality.conf.d/50-enforcing.conf"
        with open(conf_file, "w") as f:
            f.write(f"enforcing = {expected_value}\n")

        logger.info(f"[apply_enforcing] enforcing={expected_value} olarak ayarlandı ({conf_file})")

        compliant, message = check_enforcing(expected_value)
        if compliant:
            return True, f"enforcing={expected_value} olarak uygulandı ve doğrulandı."
        else:
            return False, f"Uygulama sonrası hala uyumsuz: {message}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_enforcing] Yazma hatası: {msg}")
        return False, f"enforcing ayarlanamadı: {msg}"



def check_enforce_for_root():
    """
    enforce_for_root ayarını kontrol et.
    CIS'e göre enforce_for_root aktif olmalı.
    """
    success, output = run_command([
    "grep", "-Psi", r'^\s*enforce_for_root\s*$', 
    "/etc/security/pwquality.conf",
    "/etc/security/pwquality.conf.d/*.conf"
])

    if success and output:
        return True, "enforce_for_root etkin (uyumlu)"
    return False, "enforce_for_root ayarı bulunamadı (uyumsuz)"


def apply_enforce_for_root(username=None, param=None):
    """
    5.3.3.2.8 Ensure password quality is enforced for the root user 
    enforce_for_root ayarını uygula.
    CIS'e göre aktif olmalı.
    """
    compliant, message = check_enforce_for_root()
    if compliant:
        logger.info(f"[apply_enforce_for_root] Uyumlu: {message}")
        return True, message

    logger.info(f"[apply_enforce_for_root] Uyumlu değil: {message} → Düzeltiliyor...")

    if not os.path.exists("/etc/security/pwquality.conf.d"):
        os.makedirs("/etc/security/pwquality.conf.d")

    conf_file = "/etc/security/pwquality.conf.d/50-pwroot.conf"
    try:
        with open(conf_file, "w") as f:
            f.write("enforce_for_root\n")
        logger.info(f"[apply_enforce_for_root] enforce_for_root aktif edildi ({conf_file})")
        return True, "enforce_for_root aktif edildi"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_enforce_for_root] Yazma hatası: {msg}")
        return False, f"enforce_for_root ayarlanamadı: {msg}"




def check_password_reuse(param=None):
    """
    CIS 5.3.3.3.1 - Ensure password history remember is configured
    /etc/pam.d/common-password dosyasında pam_pwhistory.so satırını kontrol eder.
    """
    try:
        expected_remember = str(param.get("remember", 24)) if param else "24"

        # pam-auth-update listesinde pwhistory aktif mi?
        result = subprocess.run(["pam-auth-update", "--list"],
                                capture_output=True, text=True, check=True)
        if "pwhistory" not in result.stdout:
            return False, "pam_pwhistory profili etkin değil."

        # common-password içinde beklenen parametre var mı?
        with open("/etc/pam.d/common-password") as f:
            lines = f.read()

        if f"pam_pwhistory.so remember={expected_remember}" in lines:
            return True, f"pam_pwhistory etkin (remember={expected_remember})"
        else:
            return False, f"pam_pwhistory bulundu ama remember={expected_remember} değil."
    except Exception as e:
        return False, f"Kontrol sırasında hata: {e}"


def apply_password_history_remember(username=None, param=None):
    """
    CIS 5.3.3.3.1 - Ensure password history remember is configured
    Eğer eksikse veya düşükse pam_pwhistory.so satırına remember=<min_remember> ekler/düzeltir.
    """
    compliant, message = check_password_reuse(param)
    if compliant:
        logger.info(f"[apply_password_history_remember] Uyumlu: {message}")
        return True, message

    logger.info(f"[apply_password_history_remember] Uyumlu değil: {message} → Düzeltiliyor...")

    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        remember_val = str(param.get("remember", 24)) if param else "24"

        profile_content = f"""Name: pwhistory
Default: yes
Priority: 1024
Conflicts: 
Password-Type: Primary
Password:
    requisite pam_pwhistory.so remember={remember_val} enforce_for_root use_authtok
"""

        with open(profile_path, "w") as f:
            f.write(profile_content)

        # pam-auth-update ile etkinleştir
        subprocess.run(["pam-auth-update", "--enable", "pwhistory", "--force"],
                       check=True)

        logger.info(f"[apply_password_history_remember] pam_pwhistory etkinleştirildi (remember={remember_val})")
        return True, f"pam_pwhistory profili eklendi ve etkinleştirildi (remember={remember_val})."
    except Exception as e:
        logger.error(f"[apply_password_history_remember] Hata: {e}")
        return False, f"pam_pwhistory uygulanamadı: {e}"




def check_password_history_enforce_for_root(min_remember):
    """
    CIS 5.3.3.3.2 - Ensure password history is enforced for the root user
    pam-auth-update uyumlu kontrol.
    """
    grep_cmd = [
        "grep", "-Psi",
        r'^\h*Password:\h+.*pam_pwhistory\.so.*enforce_for_root\b',
        PWHISTORY_PROFILE_PATH
    ]
    success, output = run_command(grep_cmd)

    if not success or not output.strip():
        return False, f"{PWHISTORY_PROFILE_PATH} içinde enforce_for_root bulunamadı"

    # remember=<N> değerini kontrol et
    match = re.search(r"remember=(\d+)", output)
    if match:
        current_value = int(match.group(1))
        if current_value >= min_remember:
            return True, f"pam_pwhistory.so enforce_for_root ve remember={current_value} (uyumlu)"
        else:
            return False, f"remember={current_value}, {min_remember} veya üstü olmalı"
    else:
        return False, "remember parametresi bulunamadı"


def apply_password_history_enforce_for_root(username=None, param=None):
    """
    CIS 5.3.3.3.2 - Ensure password history is enforced for the root user
    pam-auth-update uyumlu remediation.
    """
    param = param or {}
    min_remember = int(param.get("min_remember", 24))

    compliant, message = check_password_history_enforce_for_root(min_remember)
    if compliant:
        logger.info(f"[apply_password_history_enforce_for_root] {message}")
        return True, message

    logger.info(f"[apply_password_history_enforce_for_root] Uyumlu değil: {message} → Düzeltiliyor...")

    try:

        with open(PWHISTORY_PROFILE_PATH, "r") as f:
            lines = f.readlines()

        new_lines = []
        changed = False
        for line in lines:
            if "pam_pwhistory.so" in line and not line.strip().startswith("#"):

                if "enforce_for_root" not in line:
                    line = line.strip() + " enforce_for_root\n"

                if "remember=" in line:
                    line = re.sub(r"remember=\d+", f"remember={min_remember}", line)
                else:
                    line = line.strip() + f" remember={min_remember}\n"

                changed = True
            new_lines.append(line)

        if not changed:

            new_lines.append(
                f"Password:     requisite pam_pwhistory.so remember={min_remember} enforce_for_root try_first_pass use_authtok\n"
            )


        with open(PWHISTORY_PROFILE_PATH, "w") as f:
            f.writelines(new_lines)


        run_command(["pam-auth-update", "--enable", "pwhistory"])

        logger.info("[apply_password_history_enforce_for_root] enforce_for_root ayarlandı ve pam-auth-update çalıştırıldı")
        return True, f"pam_pwhistory.so enforce_for_root ve remember={min_remember} olarak ayarlandı"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_history_enforce_for_root] {msg}")
        return False, msg



def check_password_history_use_authtok():
    """
    CIS 5.3.3.3.3 - Ensure pam_pwhistory includes use_authtok
    /etc/pam.d/common-password dosyasında pam_pwhistory.so satırında use_authtok parametresini kontrol eder.
    """

    grep_cmd = [
        "grep", "-Psi",
        r'^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so.*use_authtok\b',
        COMMON_PASSWORD
    ]
    success, output = run_command(grep_cmd)

    if success and output.strip():
        return True, "pam_pwhistory.so satırında use_authtok bulundu (uyumlu)"
    else:
        return False, f"{COMMON_PASSWORD} içinde use_authtok bulunamadı"


def apply_password_history_use_authtok(username=None, param=None):
    """
    CIS 5.3.3.3.3 - Ensure pam_pwhistory includes use_authtok
    Eğer use_authtok eksikse pam_pwhistory.so satırına ekler.
    """
    compliant, message = check_password_history_use_authtok()
    if compliant:
        logger.info(f"[apply_password_history_use_authtok] {message}")
        return True, message

    logger.info(f"[apply_password_history_use_authtok] Uyumlu değil: {message} → Düzeltiliyor...")


    try:
        with open(COMMON_PASSWORD, "r") as f:
            lines = f.readlines()

        new_lines = []
        changed = False
        for line in lines:
            if re.search(r"pam_pwhistory\.so", line) and not line.strip().startswith("#"):
                if "use_authtok" not in line:
                    new_line = line.strip() + " use_authtok\n"
                else:
                    new_line = line
                new_lines.append(new_line)
                changed = True
            else:
                new_lines.append(line)

        if not changed:
            new_lines.append(
                "password requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok\n"
            )

        with open(COMMON_PASSWORD, "w") as f:
            f.writelines(new_lines)

        logger.info("[apply_password_history_use_authtok] use_authtok eklendi")
        return True, "pam_pwhistory.so use_authtok ile güncellendi"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_history_use_authtok] Hata: {msg}")
        return False, {msg}



def check_pam_unix_nullok():
    """
    pam_unix.so satırlarında nullok var mı kontrol eder.
    CIS 5.3.3.4.1 gereği nullok olmamalıdır.
    """
    check_cmd = [
        "grep", "-PHs",
        r'^[[:space:]]*[^#[:space:]]+[[:space:]]+pam_unix\.so.*nullok\b',
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-session-noninteractive"
    ]
    success, output = run_command(check_cmd)

    if success and output.strip():
        logger.warning(f"[CHECK][pam_unix_nullok] Uyumsuzluk bulundu. nullok geçiyor: {output.strip()}")
        return False, output.strip()
    else:
        logger.info("[CHECK][pam_unix_nullok] Uyumlu. pam_unix.so satırlarında nullok yok.")
        return True, "Uyumlu"


def apply_pam_unix_nullok(username=None, param=None):
    """
    Uyumsuzluk varsa pam_unix.so satırlarından nullok'u kaldırır.
    CIS 5.3.3.4.1 gereği nullok olmamalıdır.
    """
    try:
        compliant, details = check_pam_unix_nullok()
        if compliant:
            logger.info("[APPLY][pam_unix_nullok] Sistem zaten uyumlu, işlem yapılmadı.")
            return True, "Zaten uyumlu"

        logger.info("[APPLY][pam_unix_nullok] Uyumsuzluk tespit edildi, düzeltme başlatılıyor...")

        fix_cmd = [
            "bash", "-c",
            "for file in /etc/pam.d/common-{password,auth,account,session,session-noninteractive}; do "
            "if grep -q 'pam_unix.so' \"$file\"; then "
            "sed -i 's/\\<nullok\\>//g' \"$file\"; "
            "fi; "
            "done"
        ]
        success, output = run_command(fix_cmd)

        if not success:
            logger.error(f"[APPLY][pam_unix_nullok] Düzenleme başarısız oldu. Hata: {output}")
            return False, f"Hata: {output}"

        compliant, details = check_pam_unix_nullok()
        if compliant:
            logger.info("[APPLY][pam_unix_nullok] nullok başarıyla kaldırıldı ve sistem uyumlu hale getirildi.")
            return True, "Düzeltme uygulandı"
        else:
            logger.error("[APPLY][pam_unix_nullok] Düzeltme başarısız, nullok hala mevcut.")
            return False, "Düzeltme başarısız"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][pam_unix_nullok] Hata: {msg}")
        return False, f"Hata: {msg}"



def check_pam_unix_remember():
    """
    pam_unix.so satırlarında remember=<N> var mı kontrol eder.
    CIS 5.3.3.4.2 gereği remember kullanılmamalıdır.
    """
    check_cmd = [
        "grep", "-PHs", "--",
        r'^[[:space:]]*[^#[:space:]]+[[:space:]]+pam_unix\.so.*remember=[0-9]\+',
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-session-noninteractive"
    ]
    success, output = run_command(check_cmd)

    if success and output.strip():
        logger.warning(f"[CHECK][pam_unix_remember] Uyumsuzluk bulundu. remember kullanılıyor: {output.strip()}")
        return False, output.strip()
    else:
        logger.info("[CHECK][pam_unix_remember] Uyumlu. pam_unix.so satırlarında remember yok.")
        return True, "Uyumlu"


def apply_pam_unix_remember(username=None, param=None):
    """
    Uyumsuzluk varsa pam_unix.so satırlarından remember=<N> kısmını kaldırır.
    CIS 5.3.3.4.2 gereği remember kullanılmamalıdır.
    """
    try:
        compliant, details = check_pam_unix_remember()
        if compliant:
            logger.info("[APPLY][pam_unix_remember] Sistem zaten uyumlu, işlem yapılmadı.")
            return True, "Zaten uyumlu"

        logger.info("[APPLY][pam_unix_remember] Uyumsuzluk tespit edildi, düzeltme başlatılıyor...")

        fix_cmd = [
            "bash", "-c",
            "for file in /etc/pam.d/common-{password,auth,account,session,session-noninteractive}; do "
            "if grep -q 'pam_unix.so' \"$file\"; then "
            "sed -i -E 's/remember=[0-9]+//g' \"$file\"; "
            "fi; "
            "done"
        ]
        success, output = run_command(fix_cmd)

        if not success:
            logger.error(f"[APPLY][pam_unix_remember] Düzenleme başarısız oldu. Hata: {output}")
            return False, f"Hata: {output}"

        compliant, details = check_pam_unix_remember()
        if compliant:
            logger.info("[APPLY][pam_unix_remember] remember başarıyla kaldırıldı ve sistem uyumlu hale getirildi.")
            return True, "Düzeltme uygulandı"
        else:
            logger.error("[APPLY][pam_unix_remember] Düzeltme başarısız, remember hala mevcut.")
            return False, "Düzeltme başarısız"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][pam_unix_remember] Hata: {msg}")
        return False, f"Hata: {msg}"



def check_pam_unix_strong_hash(param=None):
    """
    CIS 5.3.3.4.3 - pam_unix.so'da güçlü hash algoritması (sha512 veya yescrypt)
    kullanılıp kullanılmadığını kontrol eder.

    Args:
        param (dict): {"algo": "sha512"} veya {"algo": "yescrypt"}.
                      Eğer None ise her ikisi de kabul edilir.
    """
    algo = None
    if param and isinstance(param, dict):
        algo = param.get("algo", "").lower()

    if algo in ("sha512", "yescrypt"):
        pattern = rf'^\h*password\s+([^#\n\r]+)\s+pam_unix\.so\s+([^#\n\r]+\s+)?{algo}\b'
    else:
        # sha512 veya yescrypt varsa yeterli
        pattern = r'^\h*password\s+([^#\n\r]+)\s+pam_unix\.so\s+([^#\n\r]+\s+)?(sha512|yescrypt)\b'

    check_cmd = ["grep", "-PH", pattern, "/etc/pam.d/common-password"]
    success, output = run_command(check_cmd)

    if success and output.strip():
        logger.info(f"[CHECK][pam_unix_strong_hash] Uyumlu. Güçlü hash algoritması kullanılıyor: {output.strip()}")
        return True, "Uyumlu"
    else:
        if algo:
            logger.warning(f"[CHECK][pam_unix_strong_hash] Uyumsuzluk. {algo} ayarlanmamış.")
            return False, f"Uyumsuz: {algo} yok"
        else:
            logger.warning("[CHECK][pam_unix_strong_hash] Uyumsuzluk. Güçlü hash algoritması ayarlanmamış.")
            return False, "Uyumsuz"


def apply_pam_unix_strong_hash(username=None, param=None):
    """
    CIS 5.3.3.4.3 -
    Uyumsuzluk varsa, pam_unix.so için güçlü hash algoritmasını ayarlar.

    Args:
        param (dict): {"algo": "sha512"} veya {"algo": "yescrypt"}.
                      Eğer None ise varsayılan sha512 kullanılır.
    """
    try:
        algo = "sha512"
        if param and isinstance(param, dict):
            algo = param.get("algo", "sha512").lower()

        compliant, _ = check_pam_unix_strong_hash(param)
        if compliant:
            logger.info("[APPLY][pam_unix_strong_hash] Sistem zaten uyumlu, işlem yapılmadı.")
            return True, "Zaten uyumlu"

        logger.info(f"[APPLY][pam_unix_strong_hash] Uyumsuzluk tespit edildi, {algo} ayarlanıyor...")

        file_to_edit = "/usr/share/pam-configs/unix"


        fix_cmd = [
            "sed", "-i",
            rf'/pam_unix\.so/ {{ s/\(pam_unix\.so.*\)/\1 {algo}/; }}',
            file_to_edit
        ]
        success, output = run_command(fix_cmd)

        if not success:
            logger.error(f"[APPLY][pam_unix_strong_hash] Dosya düzenleme başarısız. Hata: {output}")
            return False, f"Hata: {output}"


        update_cmd = ["pam-auth-update", "--enable", "unix"]
        success, output = run_command(update_cmd)

        if not success:
            logger.error(f"[APPLY][pam_unix_strong_hash] pam-auth-update başarısız. Hata: {output}")
            return False, f"Hata: {output}"


        compliant, _ = check_pam_unix_strong_hash(param)
        if compliant:
            logger.info(f"[APPLY][pam_unix_strong_hash] Güçlü hash başarıyla {algo} olarak ayarlandı.")
            return True, f"Düzeltme uygulandı: {algo}"
        else:
            logger.error("[APPLY][pam_unix_strong_hash] Düzeltme başarısız, güçlü hash hala ayarlanmamış.")
            return False, "Düzeltme başarısız"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][pam_unix_strong_hash] Hata: {msg}")
        return False, f"Hata: {msg}"



def check_pam_unix_use_authtok(param=None):
    """
    CIS 5.3.3.4.4 - Ensure pam_unix includes use_authtok
    /etc/pam.d/common-password içinde 'use_authtok' parametresini kontrol eder.
    """
    check_cmd = [
        "grep", "-PHs", "--",
        r'^\s*password\s+[^#\n\r]+\s+pam_unix\.so.*\buse_authtok\b',
        "/etc/pam.d/common-password"
    ]
    success, output = run_command(check_cmd)

    if success and output.strip():
        logger.info("[CHECK][pam_unix_use_authtok] Uyumlu. 'use_authtok' parametresi ayarlı.")
        return True, "Uyumlu"
    else:
        logger.warning("[CHECK][pam_unix_use_authtok] Uyumsuzluk. 'use_authtok' parametresi ayarlanmamış.")
        return False, "Uyumsuz"


def apply_pam_unix_use_authtok(username=None, param=None):
    """
    CIS 5.3.3.4.4 - Ensure pam_unix includes use_authtok
    Uyumsuzluk varsa /usr/share/pam-configs/unix dosyasına 'use_authtok' ekler
    ve pam-auth-update çalıştırır.
    """
    try:
        compliant, _ = check_pam_unix_use_authtok(param)
        if compliant:
            logger.info("[APPLY][pam_unix_use_authtok] Sistem zaten uyumlu, işlem yapılmadı.")
            return True, "Zaten uyumlu"

        logger.info("[APPLY][pam_unix_use_authtok] Uyumsuzluk tespit edildi, düzeltme başlatılıyor...")

        file_to_edit = "/usr/share/pam-configs/unix"

        
        fix_cmd = [
            "sed", "-i",
            r'/pam_unix\.so/ { /use_authtok/! s/$/ use_authtok/ }',
            file_to_edit
        ]
        success, output = run_command(fix_cmd)
        if not success:
            logger.error(f"[APPLY][pam_unix_use_authtok] Dosya düzenleme başarısız. Hata: {output}")
            return False, f"Hata: {output}"

        update_cmd = ["pam-auth-update", "--enable", "unix"]
        success, output = run_command(update_cmd)
        if not success:
            logger.error(f"[APPLY][pam_unix_use_authtok] pam-auth-update başarısız. Hata: {output}")
            return False, f"Hata: {output}"

        compliant, _ = check_pam_unix_use_authtok(param)
        if compliant:
            logger.info("[APPLY][pam_unix_use_authtok] 'use_authtok' başarıyla eklendi ve sistem uyumlu hale getirildi.")
            return True, "Düzeltme uygulandı"
        else:
            logger.error("[APPLY][pam_unix_use_authtok] Düzeltme başarısız, 'use_authtok' hala eksik.")
            return False, "Düzeltme başarısız"
    except Exception as e:  
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][pam_unix_use_authtok] Hata: {msg}")
        return False, f"Hata: {msg}"



##########    CIS HARICI POLITIKALAR   ##########



def check_pam_faillock():
    """
    CIS 5.3.3.x - Ensure failed login attempts are centraly logged and locked.
    Checks for pam_faillock.so usage in /etc/pam.d/common-auth.
    """
    path = "/etc/pam.d/common-auth"
    required_auth_param = "preauth"
    required_fail_param = "authfail"
    required_account_param = "account"
    
    auth_faillock_found = False
    fail_faillock_found = False
    account_faillock_found = False
    
    logger.info(f"[PAM Faillock][CHECK] Kontrol ediliyor: {path}")

    if not os.path.exists(path):
        msg = f"PAM yapılandırma dosyası ({path}) bulunamadı."
        logger.error(f"[PAM Faillock][CHECK] {msg}")
        return False, msg

    try:
        with open(path, "r") as f:
            for line in f:
                line_stripped = line.strip()
                if line_stripped.startswith("#") or not line_stripped:
                    continue
                
                parts = line_stripped.split()
                if len(parts) < 3:
                    continue

                if parts[0] == "auth" and "pam_faillock.so" in parts[2]:
                    if required_auth_param in line_stripped:
                        auth_faillock_found = True
                    if required_fail_param in line_stripped:
                        fail_faillock_found = True
                        
                elif parts[0] == "account" and "pam_faillock.so" in parts[2]:
                    account_faillock_found = True

        if not auth_faillock_found:
            return False, f"'auth required pam_faillock.so {required_auth_param}' satırı bulunamadı."
        
        if not fail_faillock_found:
            return False, f"'auth [default=die] pam_faillock.so {required_fail_param}' satırı bulunamadı."

        if not account_faillock_found:
            return False, f"'account required pam_faillock.so' satırı bulunamadı."

        msg = "pam_faillock.so her üç aşamada da doğru şekilde yapılandırılmış."
        logger.info(f"[PAM Faillock][CHECK] {msg}")
        return True, msg

    except PermissionError:
        msg = f"Yetki hatası: {path} dosyası okunamıyor. Root yetkisi gerekli."
        logger.error(f"[PAM Faillock][CHECK] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Kontrol sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[PAM Faillock][CHECK] {msg}")
        return False, msg


def apply_pam_faillock(username=None, param=None):
    """
    Ensures pam_faillock is enabled via pam-auth-update for central logging.
    """
    PROFILE_NAME = "faillock" # Debian/Ubuntu'da faillock profil adı

    success, message = check_pam_faillock()
    if success:
        return True, f"Değişiklik gerekmedi: {message}"

    try:
        # pam-auth-update aracılığıyla faillock profilini etkinleştir
        logger.info(f"[PAM Faillock][APPLY] '{PROFILE_NAME}' PAM profili etkinleştiriliyor...")
        success_update, output_update = run_command(["pam-auth-update", "--enable", PROFILE_NAME])
        
        if not success_update:
            msg = f"pam-auth-update ile '{PROFILE_NAME}' etkinleştirilemedi: {output_update}"
            logger.error(f"[PAM Faillock][APPLY] HATA: {msg}")
            return False, msg

        # Not: pam-auth-update, yapılandırmayı otomatik olarak yeniden yükler.
        
        return True, f"'{PROFILE_NAME}' PAM profili başarıyla etkinleştirildi. Tüm başarısız girişler artık loglanacak ve kilitlenecek."

    except Exception as e:
        msg = f"Uygulama sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[PAM Faillock][APPLY] HATA: {msg}")
        return False, msg