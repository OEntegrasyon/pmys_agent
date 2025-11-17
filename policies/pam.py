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
    """Belirtilen paketin kurulu sürümünü döndürür.
       Dönenler: (version_str, None) veya (None, error_msg)
    """
    try:
        success, output = run_command(["dpkg-query", "-s", package_name])
        if not success:
            return None, f"{package_name} paketi sorgulanamadı: {output.strip()}"
        lines = output.splitlines()
        status_line = next((l for l in lines if l.startswith("Status:")), None)
        version_line = next((l for l in lines if l.startswith("Version:")), None)

        if not status_line or "install ok installed" not in status_line:
            return None, f"{package_name} kurulu değil"
        if version_line:
            installed_version = version_line.split(":", 1)[1].strip()
            return installed_version, None
        return None, f"{package_name} sürümü alınamadı"
    except Exception as e:
        return None, f"{package_name} sorgulama hatası: {str(e)}"


def version_compare(v1: str, v2: str) -> int:
    """
    run_command ile dpkg --compare-versions kullanarak version compare.
    """
    try:
        ok, out = run_command(["dpkg", "--compare-versions", v1, "lt", v2])
        if ok:
            return -1

        ok, out = run_command(["dpkg", "--compare-versions", v1, "gt", v2])
        if ok:
            return 1

        return 0
    except Exception as e:
        logger.error(f"[version_compare] Hata: {e}")
        return 0


def check_libpam_runtime():
    """
    CIS 5.3.1.1 - Ensure latest version of pam is installed
    Minimum sürüm: 1.5.2-6
    Döner: (True, message) veya (False, message)
    """
    package = "libpam-runtime"
    required_version = "1.5.2-6"

    installed_version, error = get_installed_package_version(package)
    if error:
        return False, f"Kontrol: {error}"

    cmp = version_compare(installed_version, required_version)
    if cmp < 0:
        return False, f"{package} ({installed_version}) sürümü minimum gereksinimin ({required_version}) altında."
    return True, f"{package} ({installed_version}) minimum gereksinimi ({required_version}) karşılıyor."


def apply_libpam_runtime(username=None, param=None):

    """
    CIS 5.3.1.1 için uygulama (remediation).
    """
    try:
        ok, message = check_libpam_runtime()
        if ok:
            return True, f"Değişiklik gerekmedi: {message}"

        success, output = run_command(["apt-get", "update"])
        if not success:
            return False, f"apt-get update başarısız: {output}"

        success, output = run_command(["apt-get", "install", "--only-upgrade", "-y", "libpam-runtime"])
        if not success:
            return False, f"libpam-runtime yükseltilemedi: {output}"

        ok2, message2 = check_libpam_runtime()
        if ok2:
            return True, "libpam-runtime paketi güncellendi ve sürüm kontrolü başarılı."
        else:
            return False, f"Güncelleme sonrası sürüm kontrolü başarısız: {message2}"

    except Exception as e:
        logger.exception("[CIS5.3.1.1][APPLY] Hata")
        return False, f"libpam-runtime uygulama hatası: {str(e)}"

REQUIRED_VERSION = "1.5.2-6"
PACKAGE = "libpam-modules"

def check_libpam_modules():
    """
    CIS 5.3.1.2 - Ensure libpam-modules is installed (>= 1.5.2-6)
    Kullanılan get_installed_package_version signature: (version, error)
    """
    installed_version, err = get_installed_package_version(PACKAGE)
    if err:
        # get_installed_package_version zaten kurulu değil veya hata mesajı döndü
        return False, err

    if not installed_version:
        return False, f"{PACKAGE} kurulu değil veya sürümü okunamadı."

    cmp = version_compare(installed_version, REQUIRED_VERSION)
    if cmp < 0:
        return False, f"{PACKAGE} sürümü düşük: {installed_version} < {REQUIRED_VERSION}"
    
    return True, f"{PACKAGE} sürümü uygun: {installed_version} ≥ {REQUIRED_VERSION}"


def apply_libpam_modules(username=None, param=None):
    """
    CIS 5.3.1.2 - Remediation
    Paket güncelleme ve sonrasında doğrulama yapar.
    """
    try:
        ok, msg = check_libpam_modules()
        if ok:
            return True, f"Değişiklik gerekmedi: {msg}"

        logger.info("[CIS 5.3.1.2][APPLY] Paket güncellemesi başlatılıyor...")

        success, out = run_command(["apt-get", "update"])
        if not success:
            return False, f"apt-get update başarısız: {out}"

        success, out = run_command([
            "apt-get", "install", "--only-upgrade", "-y",
            "-o", "Dpkg::Options::=--force-confnew",
            PACKAGE
        ])
        if not success:
            return False, f"{PACKAGE} güncellenemedi: {out}"

        ok2, msg2 = check_libpam_modules()
        if ok2:
            return True, f"Güncelleme başarılı: {msg2}"
        else:
            return False, f"Güncelleme sonrası doğrulama başarısız: {msg2}"

    except Exception as e:
        logger.exception("[CIS 5.3.1.2][APPLY] Beklenmeyen hata")
        return False, f"Apply hatası: {str(e)}"



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

        success, output = run_command(["apt", "install", "-y", "libpam-pwquality"])
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
    CIS 5.3.2.2 - Ensure pam_faillock module is enabled
    CIS uyumlu doğrulama
    """

    try:
        results = {
            "preauth": False,
            "authfail": False,
            "account": False
        }

        # /etc/pam.d/common-auth içeriğini oku
        with open("/etc/pam.d/common-auth", "r") as f:
            auth_lines = f.readlines()

        # /etc/pam.d/common-account içeriğini oku
        with open("/etc/pam.d/common-account", "r") as f:
            account_lines = f.readlines()

        # preauth ve authfail kontrolü
        for line in auth_lines:
            line_s = line.strip()

            if "pam_faillock.so" in line_s and "preauth" in line_s and "requisite" in line_s:
                results["preauth"] = True

            if "pam_faillock.so" in line_s and "authfail" in line_s and "[default=die]" in line_s:
                results["authfail"] = True

        # account reset kontrolü
        for line in account_lines:
            line_s = line.strip()
            if "pam_faillock.so" in line_s and line_s.startswith("account"):
                results["account"] = True

        # Sonuç analizi
        if all(results.values()):
            return True, "CIS uyumlu: pam_faillock modülü doğru şekilde etkin."
        else:
            missing = [k for k, v in results.items() if not v]
            return False, f"CIS uyumsuz: Eksik bölümler: {', '.join(missing)}"

    except Exception as e:
        return False, f"Kontrol hatası: {str(e)}"


def apply_pam_faillock(username=None, param=None):
    """
    CIS 5.3.2.2 - Ensure pam_faillock module is enabled
    Debian/Pardus uyumlu pam-config profilleri oluşturur ve etkinleştirir.
    """
    logger.warning("TEST: apply_pam_faillock fonksiyonu ÇALIŞTI!")

    try:
        # Ön kontrol
        is_enabled, msg = check_pam_faillock_enabled()
        if is_enabled:
            return True, f"Değişiklik gerekmedi: {msg}"
        logger.warning("TEST: apply_pam_faillock fonksiyonu ÇALIŞTI!")
        logger.info("[PAMmmmmmmmmmmmm Faillock][APPLY] faillock profilleri oluşturuluyor...")

        # ------------------------------------------------------------
        # PROFİL 1: faillock
        # ------------------------------------------------------------

        faillock_profile = (
            "Name: Enable pam_faillock to deny access\n"
            "Default: yes\n"
            "Priority: 0\n"
            "Auth-Type: Primary\n"
            "Auth:\n"
            "    [default=die] pam_faillock.so authfail\n"
        )

        with open("/usr/share/pam-configs/faillock", "w", encoding="utf-8") as f:
            f.write(faillock_profile)

        # ------------------------------------------------------------
        # PROFİL 2: faillock_notify
        # ------------------------------------------------------------

        faillock_notify_profile = (
            "Name: Notify of failed login attempts and reset count upon success\n"
            "Default: yes\n"
            "Priority: 1024\n"
            "Auth-Type: Primary\n"
            "Auth:\n"
            "    requisite pam_faillock.so preauth\n"
            "Account-Type: Primary\n"
            "Account:\n"
            "    required pam_faillock.so\n"
        )

        with open("/usr/share/pam-configs/faillock_notify", "w", encoding="utf-8") as f:
            f.write(faillock_notify_profile)

        # ------------------------------------------------------------
        # DOSYALAR OLUŞTU MU? (Güvenlik kontrolü)
        # ------------------------------------------------------------
        import os

        if not os.path.exists("/usr/share/pam-configs/faillock"):
            return False, "faillock dosyası oluşturulamadı!"

        if not os.path.exists("/usr/share/pam-configs/faillock_notify"):
            return False, "faillock_notify dosyası oluşturulamadı!"

        logger.info("[PAM Faillock][APPLY] faillock profilleri oluşturuldu. pam-auth-update çalıştırılıyor...")

        # ------------------------------------------------------------
        # PROFİLLERİ AKTİF ET
        # ------------------------------------------------------------

        success, output = run_command(["pam-auth-update", "--enable", "faillock"])
        if not success:
            return False, f"faillock profili etkinleştirilemedi: {output}"

        success, output = run_command(["pam-auth-update", "--enable", "faillock_notify"])
        if not success:
            return False, f"faillock_notify profili etkinleştirilemedi: {output}"

        # ------------------------------------------------------------
        # SON KONTROL
        # ------------------------------------------------------------

        is_enabled, msg = check_pam_faillock_enabled()

        if is_enabled:
            return True, "pam_faillock modülü başarıyla etkinleştirildi."
        else:
            return False, "pam_faillock modülü etkinleştirilemedi."

    except Exception as e:
        logger.error(f"[CIS 5.3.2.2][APPLY] Hata: {str(e)}")
        return False, f"Hata oluştu: {str(e)}"






def check_pam_pwquality():
    """
    CIS 5.3.2.3 - Ensure pam_pwquality module is enabled
    /etc/pam.d/common-password içinde pam_pwquality.so satırı var mı kontrol eder.
    """
    try:
        if not os.path.exists("/usr/share/pam-configs/pwquality"):
            return False, "pwquality profili bulunamadı (/usr/share/pam-configs/pwquality yok)."

        success, output = run_command(["grep", "-P", r"\bpam_pwquality\.so\b", "/etc/pam.d/common-password"])
        if not success:
            return False, f"grep -P çalıştırılamadı: {output}"

        for line in output.splitlines():
            if re.match(r'^\s*#', line):
                continue
            if "pam_pwquality.so" in line:
                logger.info("[check_pam_pwquality] pam_pwquality.so modülü zaten etkin.")
                return True, "pam_pwquality.so modülü etkin."
        
        logger.warning("[check_pam_pwquality] pam_pwquality.so modülü etkin değil.")
        return False, "pam_pwquality.so modülü etkin değil."
    
    except Exception as e:
        logger.error(f"[check_pam_pwquality] Hata: {e}")
        return False, f"Hata: {e}"

        

def apply_pam_pwquality(username=None, param=None):
    """
    CIS 5.3.2.3 - Ensure pam_pwquality module is enabled
    /usr/share/pam-configs/pwquality profilini oluşturur ve pam-auth-update ile etkinleştirir.
    """
    try:
        is_enabled, msg = check_pam_pwquality()
        if is_enabled:
            return True, f"Değişiklik gerekmedi: {msg}"

        profile_path = "/usr/share/pam-configs/pwquality"
        # CIS örneğine uygun profil dosyası oluştur
        profile_content = [
            "Name: Pwquality password strength checking",
            "Default: yes",
            "Priority: 1024",
            "Conflicts: cracklib",
            "Password-Type: Primary",
            "Password:",
            " requisite pam_pwquality.so retry=3"
        ]
        with open(profile_path, "w", encoding="utf-8") as f:
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
    """
    if not os.path.exists(PWHISTORY_PROFILE_PATH):
        return False, f"{PWHISTORY_PROFILE_PATH} profili bulunamadı."

    success, output = run_command(["grep", "-E", r"pam_pwhistory\.so", "/etc/pam.d/common-password"])
    if not success:
        return False, f"grep çalıştırılamadı: {output}"

    for line in output.splitlines():
        if re.match(r'^\s*#', line):  # yorum satırlarını atla
            continue
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
        profile_content = "\n".join([
            "Name: pwhistory password history checking",
            "Default: yes",
            "Priority: 1024",
            "Password-Type: Primary",
            "Password:",
            f" {PWHISTORY_LINE}"
        ])
        with open(PWHISTORY_PROFILE_PATH, "w", encoding="utf-8") as f:
            f.write(profile_content + "\n")
        logger.info(f"[apply_pwhistory] Profil oluşturuldu: {PWHISTORY_PROFILE_PATH}")

        success, output = run_command(["pam-auth-update", "--enable", PWHISTORY_PROFILE_NAME])
        if not success:
            return False, f"pam-auth-update çalıştırılamadı: {output}"

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
DEFAULT_DENY = 5

def check_failed_attempts_lockout(expected_deny=DEFAULT_DENY):
    """
    CIS 5.3.3.1.1 - Ensure password failed attempts lockout is configured
    Koşullar:
      - /etc/security/faillock.conf -> deny = 5 (veya <=5)
      - common-auth içinde pam_faillock satırlarında deny= bulunmamalı
    """
    try:
        if not os.path.exists(FAILLOCK_CONF):
            return False, f"{FAILLOCK_CONF} bulunamadı."

        deny_value = None
        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if re.match(r'^\s*#', line):
                    continue
                if re.match(r'^\s*deny\s*=', line):
                    try:
                        deny_value = int(line.split("=")[1].strip())
                    except:
                        pass

        if deny_value is None:
            return False, "deny parametresi faillock.conf içinde bulunamadı."
        if deny_value > expected_deny:
            return False, f"deny={deny_value}, beklenen <= {expected_deny}"

        # common-auth içinde hatalı deny= var mı?
        cmd = [
            "grep", "-Pi",
            r'^\s*auth.*pam_faillock\.so.*\bdeny\s*=\s*(0|[6-9]|[1-9][0-9]+)\b',
            "/etc/pam.d/common-auth"
        ]
        ok, out = run_command(cmd)
        if ok and out.strip():
            return False, f"common-auth içinde hatalı deny parametresi var:\n{out}"

        return True, f"deny={deny_value}, CIS 5.3.3.1.1 uyumlu."

    except Exception as e:
        return False, f"Hata: {e}"




def apply_failed_attempts_lockout(username=None, param=None):
    """
    CIS 5.3.3.1.1 - deny değerini 5 yapar, yoksa ekler.
    common-auth içinde deny= parametresini temizler.
    """
    try:
        param = param or {}
        expected_deny = param.get("deny", DEFAULT_DENY)

        ok, msg = check_failed_attempts_lockout(expected_deny)
        if ok:
            return True, f"Ayar zaten uygun: {msg}"

        run_command(["sed", "-Ei", "s/^\\s*deny\\s*=.*/deny = 5/", FAILLOCK_CONF])

        run_command(["bash", "-c", f"grep -Pq '^\\s*deny\\s*=' {FAILLOCK_CONF} || echo 'deny = 5' >> {FAILLOCK_CONF}"])

        run_command([
            "sed", "-Ei",
            "/pam_faillock.so/ s/ deny=[0-9]+//g",
            "/etc/pam.d/common-auth"
        ])

        ok, msg = check_failed_attempts_lockout(expected_deny)
        if ok:
            return True, f"Başarıyla uygulandı. ({msg})"
        else:
            return False, f"Uygulandı fakat doğrulama başarısız: {msg}"

    except Exception as e:
        return False, f"Hata: {e}"



DEFAULT_UNLOCK = 900


def check_unlock_time(param=None):
    """
    CIS 5.3.3.1.2 - Ensure password unlock time is configured
    unlock_time 0 veya >= 900 olmalıdır ve PAM dosyalarında unlock_time olmamalıdır.
    """

    try:
        expected = int((param or {}).get("unlock_time", DEFAULT_UNLOCK))
        if expected < 900 and expected != 0:
            expected = 900

        if not os.path.exists(FAILLOCK_CONF):
            return False, f"{FAILLOCK_CONF} dosyası yok."

        # unlock_time kontrol
        with open(FAILLOCK_CONF, "r") as f:
            data = f.read()

        match = re.search(r'^\s*unlock_time\s*=\s*(\d+)', data, re.MULTILINE)
        if not match:
            return False, "unlock_time ayarı dosyada bulunamadı."

        current = int(match.group(1))
        if current != 0 and current < expected:
            return False, f"unlock_time={current}, en az {expected} olmalı."

        # PAM dosyalarında unlock_time olmamalı
        cmd = r"grep -Pi '^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so\s+.*unlock_time\s*=' /etc/pam.d/common-auth"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        if result.stdout.strip():
            return False, f"PAM içinde unlock_time kaldırılmalı:\n{result.stdout.strip()}"

        return True, f"unlock_time uygundur: {current}"

    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_unlock_time(username=None, param=None):
    """
    CIS 5.3.3.1.2 - unlock_time = 0 veya >= 900 olacak, PAM içinde unlock_time olmayacak
    """

    try:
        expected = int((param or {}).get("unlock_time", DEFAULT_UNLOCK))
        if expected < 900 and expected != 0:
            expected = 900

        ok, msg = check_unlock_time({"unlock_time": expected})
        if ok:
            return True, f"Zaten uygun: {msg}"

        # unlock_time satırını güncelle veya ekle
        lines, found = [], False
        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if re.match(r'^\s*unlock_time\s*=', line):
                    lines.append(f"unlock_time = {expected}\n")
                    found = True
                else:
                    lines.append(line)

        if not found:
            lines.append(f"\nunlock_time = {expected}\n")

        with open(FAILLOCK_CONF, "w") as f:
            f.writelines(lines)

        logger.info(f"[CIS 5.3.3.1.2] unlock_time {expected} olarak ayarlandı.")

        # PAM configlerinde unlock_time parametresini temizle
        for fpath in glob.glob("/usr/share/pam-configs/*"):
            try:
                with open(fpath, "r") as f:
                    data = f.read()

                if "unlock_time=" not in data:
                    continue

                cleaned = "\n".join(
                    " ".join(p for p in line.split() if not p.startswith("unlock_time="))
                    for line in data.splitlines()
                )

                with open(fpath, "w") as f:
                    f.write(cleaned)

                logger.info(f"[CIS 5.3.3.1.2] unlock_time kaldırıldı: {fpath}")

            except Exception as e:
                logger.warning(f"[CIS 5.3.3.1.2] Dosya düzenlenemedi {fpath}: {e}")

        # Son kontrol
        ok2, msg2 = check_unlock_time({"unlock_time": expected})
        if ok2:
            return True, f"Uygulandı: {msg2}"
        else:
            return False, f"Uygulandı ama doğrulama başarısız: {msg2}"

    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.2][APPLY] Hata: {e}")
        return False, str(e)


DEFAULT_ROOT_UNLOCK = 60  # CIS önerisi: >= 60 saniye


def _safe_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def check_root_account_lock(param=None):
    """
    CIS 5.3.3.1.3 - Root hesabı da kilitlemeye dahil edilmeli
    - even_deny_root mevcut olmalı
    - root_unlock_time yoksa tamam, varsa >=60 olmalı
    - PAM içinde root_unlock_time= parametresi kullanılmamalı
    """
    try:
        min_time = int((param or {}).get("root_unlock_time", 60))
        if min_time < 60:
            min_time = 60

        if not os.path.exists(FAILLOCK_CONF):
            return False, f"{FAILLOCK_CONF} bulunamadı."

        text = open(FAILLOCK_CONF, "r").read()

        if not re.search(r"^\s*even_deny_root\b", text, re.MULTILINE):
            return False, "even_deny_root satırı eksik."

        m = re.search(r"^\s*root_unlock_time\s*=\s*(\d+)", text, re.MULTILINE)
        if m:
            val = int(m.group(1))
            if val == 0:
                return False, "root_unlock_time=0 olamaz (DoS riski)"
            if val < 60:
                return False, f"root_unlock_time={val}, 60 veya daha büyük olmalı."

        bad = run_command([
            "grep", "-Pi",
            r"^\s*auth\s+.*pam_faillock\.so.*root_unlock_time",
            "/etc/pam.d/common-auth"
        ])
        if bad[0] and bad[1].strip():
            return False, "PAM içinde root_unlock_time argümanı kullanılmamalı."

        return True, "Root faillock ayarları CIS 5.3.3.1.3 ile uyumlu."

    except Exception as e:
        return False, f"Kontrol hatası: {e}"


def apply_root_account_lock(username=None, param=None):
    """
    CIS 5.3.3.1.3 - Root için lockout ayarlarını uygula
    - even_deny_root ekle
    - root_unlock_time yoksa eklenmez, varsa min 60 yapılır
    - PAM içindeki root_unlock_time argümanlarını temizler
    - pam-auth-update kullanılmaz
    """
    try:
        param = param or {}
        required_time = int(param.get("root_unlock_time", 60))
        if required_time < 60:
            required_time = 60

        ok, msg = check_root_account_lock({"root_unlock_time": required_time})
        if ok:
            return True, f"Gerek yok, zaten uygun: {msg}"

        shutil.copy2(FAILLOCK_CONF, FAILLOCK_CONF + ".bak")

        lines = []
        has_even = False
        found_root_time = False

        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                if re.match(r"^\s*even_deny_root\b", line):
                    has_even = True
                    lines.append("even_deny_root\n")
                elif re.match(r"^\s*root_unlock_time\s*=", line):
                    found_root_time = True
                    lines.append(f"root_unlock_time = {required_time}\n")
                else:
                    lines.append(line)

        if not has_even:
            lines.append("\neven_deny_root\n")

        if found_root_time:  # sadece varsa min 60 yap, yoksa ekleme
            pass

        with open(FAILLOCK_CONF, "w") as f:
            f.writelines(lines)

        # 2) PAM içinden root_unlock_time temizle (varsa)
        ok2, files = run_command(
            ["grep", "-Pl", r"pam_faillock\.so.*root_unlock_time", "/usr/share/pam-configs"]
        )
        if ok2 and files.strip():
            for fpath in files.splitlines():
                txt = open(fpath).read().splitlines()
                cleaned = [" ".join(p for p in ln.split() if not p.startswith("root_unlock_time=")) for ln in txt]
                open(fpath, "w").write("\n".join(cleaned) + "\n")

        return True, "CIS 5.3.3.1.3 root lockout ayarları başarıyla uygulandı."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.3][APPLY] {e}")
        return False, str(e)



PWQUALITY_CONF = "/etc/security/pwquality.conf"
PWQUALITY_CONF_DIR = "/etc/security/pwquality.conf.d/"
PWQUALITY_CONF_FILE = f"{PWQUALITY_CONF_DIR}50-pwdifok.conf"
PAM_CONFIG_DIR = "/usr/share/pam-configs/"

def check_pwquality_difok(difok_min=2):
    """
    CIS 5.3.3.2.1 - Ensure password number of changed characters is configured
    """
    try:
        cmd_check = [
            "bash", "-c",
            "grep -Psi -- '^\\s*difok\\s*=\\s*([2-9]|[1-9][0-9]+)\\b' "
            "/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
        ]
        success, output = run_command(cmd_check)

        if not success or not output.strip():
            return False, "difok >= 2 ayarı bulunamadı."

        cmd_pam = [
            "bash", "-c",
            "grep -Psi -- '^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*difok\\s*=\\s*([0-1])\\b' "
            "/etc/pam.d/common-password"
        ]
        success, output = run_command(cmd_pam)

        if success and output.strip():
            return False, f"PAM içinde uygunsuz difok değeri tespit edildi:\n{output}"

        return True, "difok yapılandırması CIS gereksinimine uygun."

    except Exception as e:
        return False, f"Hata: {e}"



def apply_pwquality_difok(username=None, param=None):
    """
    CIS 5.3.3.2.1 - Uygulama: difok >= 2 olacak şekilde ayarlanır
    """
    try:
        difok = 2
        if isinstance(param, dict):
            difok = int(param.get("difok", 2))
        elif param is not None:
            difok = int(param)

        is_ok, _ = check_pwquality_difok(difok)
        if is_ok:
            return True, f"difok zaten {difok} veya daha büyük olarak ayarlı."

        run_command(["sed", "-ri", r"s/^\s*difok\s*=/# &/", PWQUALITY_CONF])
        run_command(["mkdir", "-p", PWQUALITY_CONF_DIR])

        cmd_write = ["bash", "-c", f"printf '\\ndifok = {difok}\\n' > {PWQUALITY_CONF_FILE}"]
        success, output = run_command(cmd_write)

        if not success:
            return False, f"difok yazılamadı: {output}"

        cmd_clean = [
            "bash", "-c",
            f"grep -Pl '\\bpam_pwquality\\.so\\b.*difok' {PAM_CONFIG_DIR}* 2>/dev/null"
        ]
        success, files = run_command(cmd_clean)

        if success and files.strip():
            for file in files.splitlines():
                run_command(["sed", "-ri", r"s/\bdifok\s*=\s*\d+\b//g", file])

        return True, f"difok {difok} olarak ayarlandı ve PAM içindeki eski değerler temizlendi."

    except Exception as e:
        msg = f"Hata: {str(e)}" 
        logger.error(f"[CIS 5.3.3.2.1 ][APPLY] {msg}") 
        return False, f"Hata: {msg}"



PWQUALITY_FILE = os.path.join(PWQUALITY_CONF_DIR, "50-pwlength.conf")
CIS_MINLEN = 14  # CIS önerilen minimum

def check_min_password_length(param=None):
    """
    CIS 5.3.3.2.2 - Ensure minimum password length is configured
    Gereksinimler:
      - /etc/security/pwquality.conf veya .d/*.conf içinde minlen >= 14 olmalı
      - /etc/pam.d/common-password içinde pam_pwquality.so satırlarında minlen <=13 olmamalı
    """
    try:
        minlen = CIS_MINLEN
        if param and "minlen" in param:
            minlen = max(CIS_MINLEN, int(param["minlen"]))

        logger.info(f"[check_min_password_length] minlen >= {minlen} kontrol ediliyor...")

        success, output = run_command([
            "bash", "-c",
            f"grep -Psi '^\\s*minlen\\s*=\\s*(1[4-9]|[2-9][0-9]|[1-9][0-9]{{2,}})\\b' "
            f"{PWQUALITY_CONF} {PWQUALITY_CONF_DIR}*.conf"
        ])
        if not (success and output.strip()):
            return False, f"pwquality.conf veya .d dizininde minlen {minlen} altında veya tanımsız."

        # PAM içinde minlen 0-13 aranmamalı (bulunursa hatalı)
        success, pam_output = run_command([
            "grep", "-Psi",
            r"^\s*password.*pam_pwquality\.so.*minlen\s*=\s*([0-9]|1[0-3])\b",
            "/etc/pam.d/common-password"
        ])
        if success and pam_output.strip():
            return False, f"common-password içinde düşük minlen değeri bulundu:\n{pam_output}"

        return True, f"minlen >= {minlen} doğru yapılandırılmış."

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

        run_command(["sed", "-ri", r"s/^\s*minlen\s*=/# &/", PWQUALITY_CONF])

        run_command(["mkdir", "-p", PWQUALITY_CONF_DIR])

        success, output = run_command([
            "bash", "-c", f"printf '\\nminlen = {minlen}\\n' > {PWQUALITY_FILE}"
        ])
        if not success:
            return False, f"Minlen değeri yazılamadı: {output}"

        success, files = run_command([
            "bash", "-c",
            "grep -Pl '\\bpam_pwquality\\.so\\s+([^#\\n\\r]+\\s+)?minlen\\b' /usr/share/pam-configs/* 2>/dev/null"
        ])
        if success and files.strip():
            for file in files.splitlines():
                run_command(["sed", "-ri", r"s/\bminlen\s*=\s*\d+\b//g", file])
                logger.info(f"[apply_min_password_length] PAM minlen temizlendi: {file}")

        return True, f"minlen {minlen} olarak ayarlandı ve eski tanımlar temizlendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.2][APPLY] {msg}")
        return False, msg



PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwcomplexity.conf"

def check_pw_complexity(param: dict) -> (bool, str):
    """
    CIS 5.3.3.2.3 - Ensure password complexity is configured
    Kontrol edilen parametreler: minclass, dcredit, ucredit, lcredit, ocredit
    """
    try:
        conf_files = [PWQUALITY_CONF]
        if os.path.isdir("/etc/security/pwquality.conf.d/"):
            conf_files.extend(
                os.path.join("/etc/security/pwquality.conf.d/", f)
                for f in os.listdir("/etc/security/pwquality.conf.d/")
                if f.endswith(".conf")
            )

        content = ""
        for file in conf_files:
            if not os.path.exists(file):
                continue
            try:
                with open(file, "r") as f:
                    content += f.read() + "\n"
            except Exception:
                continue

        for key, expected in param.items():
            match = re.search(rf'^\s*{key}\s*=\s*(-?\d+)', content, re.MULTILINE)
            if not match:
                return False, f"{key} parametresi bulunamadı."
            value = int(match.group(1))
            if key == "minclass" and value < int(expected):
                return False, f"{key}={value}, beklenen ≥ {expected}"
            elif key != "minclass" and value > 0:
                return False, f"{key}={value}, 0 veya negatif olmalı (ör: -1)"

        pam_check = subprocess.run([
            "grep", "-Psi",
            r"pam_pwquality\.so.*(minclass|[dulo]credit)",
            "/etc/pam.d/common-password"
        ], stdout=subprocess.PIPE, text=True)
        if pam_check.stdout.strip():
            return False, f"common-password içinde uygunsuz pam_pwquality argümanları bulundu:\n{pam_check.stdout}"

        return True, "Parola karmaşıklığı CIS gereksinimlerine uygun."
    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_pw_complexity(username=None, param=None):
    """
    CIS 5.3.3.2.3 - Apply password complexity parameters
    param örnek: {"minclass": 3, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1}
    """
    try:
        param = param or {"minclass": 3, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1}

        ok, msg = check_pw_complexity(param)
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        run_command(["sed", "-ri", r"/^\s*(minclass|[dulo]credit)\s*=/d", PWQUALITY_CONF])

        os.makedirs("/etc/security/pwquality.conf.d/", exist_ok=True)

        with open(PWQUALITY_CONF_D, "w") as f:
            for key in ["minclass", "dcredit", "ucredit", "lcredit", "ocredit"]:
                f.write(f"{key} = {param.get(key, -1)}\n")

        pam_conf = PAM_CONFIG_DIR
        success, output = run_command([
            "grep", "-Pl",
            r"pam_pwquality\.so.*(minclass|[dulo]credit)",
            f"{pam_conf}*"
        ])
        if success and output:
            for file in output.splitlines():
                run_command(["sed", "-ri", r"s/\b(minclass|[dulo]credit)\s*=\s*-?\d+\b//g", file])
                logger.info(f"[apply_pw_complexity] {file} içindeki eski argümanlar temizlendi.")

        return True, f"Parola karmaşıklık ayarları başarıyla uygulandı: {param}"
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.3][APPLY] {msg}")
        return False, f"Hata: {msg}"




PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwrepeat.conf"
COMMON_PASSWORD = "/etc/pam.d/common-password"

def check_maxrepeat(expected_value=3):
    """
    """
    try:
        logger.info("[check_maxrepeat] Parola maxrepeat ayarları kontrol ediliyor...")

        current_value = None
        conf_files = [PWQUALITY_CONF]

        if os.path.isdir("/etc/security/pwquality.conf.d/"):
            conf_files += [
                os.path.join("/etc/security/pwquality.conf.d/", f)
                for f in os.listdir("/etc/security/pwquality.conf.d/")
                if f.endswith(".conf")
            ]

        for file in conf_files:
            try:
                with open(file, "r") as f:
                    for line in f:
                        if re.match(r"^\s*maxrepeat\s*=", line):
                            current_value = int(line.split("=")[1].strip())
                            break
            except Exception:
                continue

        # PAM tarafında uygunsuz maxrepeat var mı?
        pam_check = subprocess.run([
            "grep", "-Psi",
            r"^\s*password.*pam_pwquality\.so.*maxrepeat\s*=\s*(0|[4-9]|[1-9][0-9]+)\b",
            COMMON_PASSWORD
        ], stdout=subprocess.PIPE, text=True)

        if pam_check.stdout.strip():
            return False, f"common-password içinde uygunsuz maxrepeat bulundu:\n{pam_check.stdout}"

        if current_value is None:
            return False, "maxrepeat parametresi tanımlı değil."

        if 1 <= current_value <= expected_value:
            return True, f"maxrepeat uygun: {current_value}"
        else:
            return False, f"maxrepeat uygunsuz: {current_value} (1–{expected_value} olmalı, 0 olmamalı)"
    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_maxrepeat(username=None, param=None):
    """
    CIS 5.3.3.2.4 - Ensure password same consecutive characters is configured
    param örnek: {"maxrepeat": 3}
    """
    try:
        desired_value = int(param.get("maxrepeat", 3)) if param else 3
        logger.info(f"[apply_maxrepeat] maxrepeat {desired_value} olarak uygulanacak.")

        ok, msg = check_maxrepeat(expected_value=desired_value)
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        #  Eski tanımları kaldır
        run_command(["sed", "-ri", r"/^\s*maxrepeat\s*=/d", PWQUALITY_CONF])

        #  pwquality.conf.d dizinini oluştur
        os.makedirs(os.path.dirname(PWQUALITY_CONF_D), exist_ok=True)

        #  Yeni değeri yaz
        with open(PWQUALITY_CONF_D, "w") as f:
            f.write(f"maxrepeat = {desired_value}\n")
        logger.info(f"[apply_maxrepeat] {PWQUALITY_CONF_D} dosyasına maxrepeat = {desired_value} yazıldı.")

        # PAM modüllerinde uygunsuz tanımları temizle
        pam_dir = "/usr/share/pam-configs"
        success, output = run_command([
            "grep", "-Pl",
            r"pam_pwquality\.so.*maxrepeat",
            f"{pam_dir}/*"
        ])
        if success and output:
            for file in output.splitlines():
                run_command(["sed", "-ri", r"s/\bmaxrepeat\s*=\s*[0-9]+\b//g", file])
                logger.info(f"[apply_maxrepeat] {file} içindeki maxrepeat argümanı temizlendi.")

        return True, f"maxrepeat = {desired_value} olarak ayarlandı."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.4 ][APPLY] {msg}")
        return False, f"Hata: {msg}"



    
PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwmaxsequence.conf"
PWQUALITY_DIR = "/etc/security/pwquality.conf.d"

def check_maxsequence(expected_value=3):
    """
    CIS 5.3.3.2.5 - Ensure password maximum sequential characters is configured
    Gereksinimler:
      - maxsequence 1–3 aralığında olmalı (0 olmamalı)
      - common-password içinde pam_pwquality.so maxsequence 0 veya >3 olmamalı
    """
    try:
        logger.info("[check_maxsequence] Parola maxsequence ayarları kontrol ediliyor...")

        conf_files = [PWQUALITY_CONF]
        if os.path.isdir(PWQUALITY_DIR):
            conf_files.extend(
                os.path.join(PWQUALITY_DIR, f)
                for f in os.listdir(PWQUALITY_DIR)
                if f.endswith(".conf")
            )

        # maxsequence değerini tespit et
        found_value = None
        success, output = run_command([
            "grep", "-Psi", r"^\s*maxsequence\s*=\s*[0-9]+", *conf_files
        ])
        if success and output:
            for line in output.splitlines():
                match = re.search(r"maxsequence\s*=\s*(\d+)", line)
                if match:
                    found_value = int(match.group(1))
                    break

        # PAM içinde hatalı tanım var mı kontrol et
        success, pam_output = run_command([
            "grep", "-Psi",
            r"^\s*password.*pam_pwquality\.so.*maxsequence\s*=\s*(0|[4-9]|[1-9][0-9]+)\b",
            COMMON_PASSWORD
        ])

        if success and pam_output.strip():
            return False, f"common-password içinde hatalı maxsequence parametresi bulundu:\n{pam_output}"

        # Değeri değerlendir
        if found_value is None:
            return False, "maxsequence parametresi bulunamadı."
        if found_value == 0:
            return False, f"maxsequence={found_value}, 0 olmamalı"
        if found_value > expected_value:
            return False, f"maxsequence={found_value}, {expected_value} veya daha az olmalı"

        return True, f"maxsequence={found_value}, CIS uyumlu."
    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_maxsequence(username=None, param=None):
    """
    CIS 5.3.3.2.5 - Ensure password maximum sequential characters is configured
    param örnek: {"value": 3}
    """
    try:
        desired_value = int(param.get("value", 3)) if param else 3
        logger.info(f"[apply_maxsequence] maxsequence {desired_value} olarak uygulanacak...")

        ok, msg = check_maxsequence(expected_value=desired_value)
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        # Eski tanımı tamamen kaldır
        run_command(["sed", "-ri", r"/^\s*maxsequence\s*=/d", PWQUALITY_CONF])

        # .d dizini yoksa oluştur
        os.makedirs(os.path.dirname(PWQUALITY_CONF_D), exist_ok=True)

        # Yeni dosyaya ayar yaz
        with open(PWQUALITY_CONF_D, "w") as f:
            f.write(f"maxsequence = {desired_value}\n")

        logger.info(f"[apply_maxsequence] {PWQUALITY_CONF_D} dosyasına maxsequence = {desired_value} yazıldı.")

        # PAM modüllerinde uygunsuz tanımları temizle
        pam_dir = "/usr/share/pam-configs"
        success, output = run_command([
            "grep", "-Pl",
            r"pam_pwquality\.so.*maxsequence",
            f"{pam_dir}/*"
        ])
        if success and output:
            for file in output.splitlines():
                run_command(["sed", "-ri", r"s/\bmaxsequence\s*=\s*[0-9]+\b//g", file])
                logger.info(f"[apply_maxsequence] {file} içindeki maxsequence argümanı temizlendi.")

        return True, f"maxsequence = {desired_value} olarak ayarlandı ve eski tanımlar temizlendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.5][APPLY] {msg}")
        return False, f"Hata: {msg}"


DICTCHECK_CONF = os.path.join(PWQUALITY_DIR, "50-dictcheck.conf")


PAM_CONFIG_DIR = "/usr/share/pam-configs"

def check_dictcheck(expected_value=1):
    """
    CIS 5.3.3.2.6 - Ensure password dictionary check is enabled
    dictcheck=0 bulunmamalı.
    """
    try:
        conf_files = [PWQUALITY_CONF]
        if os.path.isdir(PWQUALITY_DIR):
            conf_files.extend(
                os.path.join(PWQUALITY_DIR, f)
                for f in os.listdir(PWQUALITY_DIR)
                if f.endswith(".conf")
            )

        # pwquality.conf ve .d dizininde dictcheck=0 var mı?
        for path in conf_files:
            if not os.path.isfile(path):
                continue
            with open(path, "r") as f:
                for line in f:
                    if re.match(r"^\s*dictcheck\s*=\s*0\b", line):
                        return False, f"{path} içinde dictcheck=0 bulundu."

        # PAM tanımlarında dictcheck=0 var mı?
        if os.path.isfile(COMMON_PASSWORD):
            with open(COMMON_PASSWORD, "r") as f:
                for line in f:
                    if "pam_pwquality.so" in line and "dictcheck=0" in line:
                        return False, f"{COMMON_PASSWORD} içinde dictcheck=0 bulundu."

        # Özel dosyada dictcheck=1 tanımı var mı?
        if os.path.isfile(DICTCHECK_CONF):
            with open(DICTCHECK_CONF, "r") as f:
                match = re.search(r"^\s*dictcheck\s*=\s*(\d+)", f.read(), re.MULTILINE)
                if match and int(match.group(1)) == expected_value:
                    return True, f"dictcheck = {expected_value} etkin ({DICTCHECK_CONF})"
                else:
                    return False, f"{DICTCHECK_CONF} içinde dictcheck değeri beklenenden farklı."

        # dictcheck=0 bulunmadı ama 1 tanımı da yoksa
        return False, "dictcheck=1 tanımı açıkça bulunamadı (varsayılan olabilir)."

    except Exception as e:
        return False, f"Hata: {e}"


def apply_dictcheck(username=None, param=None):
    """
    CIS 5.3.3.2.6 - Apply
    dictcheck=1 olacak şekilde yapılandırır.
    """
    try:
        expected_value = int(param.get("value", 1)) if param else 1
        ok, msg = check_dictcheck(expected_value)

        if ok:
            return True, f"Zaten uyumlu: {msg}"

        logger.info(f"[apply_dictcheck] Uyumsuz: {msg} → Düzeltiliyor...")

        # pwquality.conf ve .d altındaki dictcheck=0 satırlarını yorumla
        for path in [PWQUALITY_CONF] + [
            os.path.join(PWQUALITY_DIR, f)
            for f in os.listdir(PWQUALITY_DIR) if f.endswith(".conf")
        ] if os.path.isdir(PWQUALITY_DIR) else [PWQUALITY_CONF]:
            if os.path.isfile(path):
                run_command(["sed", "-ri", r"s/^\s*dictcheck\s*=\s*0\b/# &/", path])

        # common-password ve pam-configs içindeki dictcheck=0'ları temizle
        if os.path.isfile(COMMON_PASSWORD):
            run_command(["sed", "-ri", r"s/\bdictcheck\s*=\s*0\b//g", COMMON_PASSWORD])

        success, output = run_command(["grep", "-Pl", r"pam_pwquality\.so.*dictcheck", f"{PAM_CONFIG_DIR}/*"])
        if success and output:
            for f in output.splitlines():
                run_command(["sed", "-ri", r"s/\bdictcheck\s*=\s*\d+\b//g", f])
                logger.info(f"[apply_dictcheck] {f} içindeki dictcheck parametresi temizlendi.")

        # Yeni dosyayı oluştur
        os.makedirs(PWQUALITY_DIR, exist_ok=True)
        with open(DICTCHECK_CONF, "w") as f:
            f.write(f"dictcheck = {expected_value}\n")

        logger.info(f"[apply_dictcheck] dictcheck={expected_value} olarak ayarlandı ({DICTCHECK_CONF})")

        # Son kontrol
        final_ok, final_msg = check_dictcheck(expected_value)
        if final_ok:
            return True, final_msg
        else:
            return False, f"Ayar uygulandı ancak doğrulama başarısız: {final_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.6][APPLY] {msg}")
        return False, msg

ENFORCING_CONF = os.path.join(PWQUALITY_DIR, "50-enforcing.conf")


def check_enforcing(expected_value=1):
    """
    CIS 5.3.3.2.7 - Ensure password quality checking is enforced
    enforcing=0 olmamalı ve enforcing=1 aktif olmalı
    """

    # 1) pwquality config'lerde enforcing=0 var mı?
    cmd1 = [
        "grep", "-PHsi", r"^\h*enforcing\h*=\h*0\b",
        PWQUALITY_CONF, f"{PWQUALITY_DIR}/*.conf"
    ]
    ok1, out1 = run_command(cmd1)
    if ok1 and out1.strip():
        return False, f"enforcing=0 bulundu:\n{out1}"

    # 2) PAM common-password içinde override enforcing=0 var mı?
    cmd2 = [
        "grep", "-PHsi",
        r"^\h*password\h+[^#\n\r]+\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b",
        COMMON_PASSWORD
    ]
    ok2, out2 = run_command(cmd2)
    if ok2 and out2.strip():
        return False, f"PAM override enforcing=0 bulundu:\n{out2}"

    # 3) enforcing=1 ayarı 50-enforcing.conf içinde tanımlı mı?
    if os.path.isfile(ENFORCING_CONF):
        with open(ENFORCING_CONF, "r") as f:
            content = f.read()
        m = re.search(r"^\s*enforcing\s*=\s*(\d+)", content, re.MULTILINE)
        if m and int(m.group(1)) == expected_value:
            return True, f"enforcing={expected_value} aktif ({ENFORCING_CONF})"

    return False, "enforcing=1 tanımı bulunamadı."


def apply_enforcing(username=None, param=None):
    """
    CIS 5.3.3.2.7 - enforcing=1 olacak ve hiçbir yerde =0 olmayacak
    """
    expected_value = int(param.get("value", 1)) if param else 1

    ok, msg = check_enforcing(expected_value)
    if ok:
        return True, f"Zaten uyumlu: {msg}"

    logger.info(f"[apply_enforcing] Uyum dışı: {msg} → düzeltiliyor...")

    # 1) PAM config override içinde enforcing=0 geçenleri bul ve temizle
    cmd3 = [
        "grep", "-Pl",
        r"\bpam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b",
        f"{PAM_CONFIG_DIR}/*"
    ]
    ok3, out3 = run_command(cmd3)
    if ok3 and out3.strip():
        for conf in out3.splitlines():
            run_command(["sed", "-ri", r"s/\benforcing\s*=\s*0\b//g", conf])
            logger.info(f"[apply_enforcing] PAM override temizlendi: {conf}")

    # 2) pwquality.conf ve .d/*.conf içinde enforcing=0 olanları yorum satırı yap
    cmd4 = [
        "sed", "-ri",
        r"s/^\s*enforcing\s*=\s*0/# &/",
        PWQUALITY_CONF, f"{PWQUALITY_DIR}/*.conf"
    ]
    run_command(cmd4)
    logger.info("[apply_enforcing] pwquality enforcing=0 satırları yorumlandı")

    # 3) enforcing=1 tanımını 50-enforcing.conf içine yaz
    os.makedirs(PWQUALITY_DIR, exist_ok=True)
    with open(ENFORCING_CONF, "w") as f:
        f.write(f"enforcing = {expected_value}\n")

    logger.info(f"[apply_enforcing] enforcing={expected_value} yazıldı: {ENFORCING_CONF}")

    # 4) Son doğrulama
    final_ok, final_msg = check_enforcing(expected_value)
    return final_ok, final_msg


PWQUALITY_FILE = os.path.join(PWQUALITY_DIR, "50-pwroot.conf")

def check_enforce_for_root():
    """
    CIS 5.3.3.2.8 - Ensure password quality is enforced for the root user
    enforce_for_root aktif olmalı.
    """
    try:
        config_files = [PWQUALITY_CONF] + glob.glob(f"{PWQUALITY_DIR}/*.conf")
        found = False
        for file in config_files:
            if os.path.exists(file):
                with open(file, "r") as f:
                    for line in f:
                        if re.match(r"^[ \t]*enforce_for_root\b", line):
                            found = True
                            break
        if found:
            return True, "enforce_for_root aktif (uyumlu)"
        return False, "enforce_for_root bulunamadı (uyumsuz)"
    except Exception as e:
        return False, f"Hata: {e}"


def apply_enforce_for_root(username=None, param=None):
    """
    5.3.3.2.8 - Ensure password quality is enforced for the root user
    CIS'e tam uyumlu sürüm
    """
    try:
        ok, msg = check_enforce_for_root()
        if ok:
            logger.info(f"[apply_enforce_for_root] Zaten uyumlu: {msg}")
            return True, msg

        logger.info(f"[apply_enforce_for_root] Uyumsuz: {msg} → Düzeltiliyor...")

        for file in [PWQUALITY_CONF] + glob.glob(f"{PWQUALITY_DIR}/*.conf"):
            if os.path.exists(file):
                run_command(["sed", "-ri", r"s/^\s*enforce_for_root\b/# &/", file])

        os.makedirs(PWQUALITY_DIR, exist_ok=True)

        with open(PWQUALITY_FILE, "w") as f:
            f.write("enforce_for_root\n")

        logger.info(f"[apply_enforce_for_root] enforce_for_root eklendi ({PWQUALITY_FILE})")

        ok, msg = check_enforce_for_root()
        return ok, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_enforce_for_root] Yazma hatası: {msg}")
        return False, f"enforce_for_root ayarlanamadı: {msg}"



PAM_PROFILE = "/usr/share/pam-configs/pwhistory"
DEFAULT_REMEMBER = 24


def check_password_reuse(param=None):
    """
    CIS 5.3.3.3.1 - Ensure password history remember is configured
    """
    try:
        expected_remember = int(param.get("remember", DEFAULT_REMEMBER)) if param else DEFAULT_REMEMBER

        if not os.path.exists(COMMON_PASSWORD):
            return False, f"{COMMON_PASSWORD} bulunamadı."

        with open(COMMON_PASSWORD, "r") as f:
            content = f.read()

        # pam_pwhistory.so satırı var mı?
        match = re.search(r"pam_pwhistory\.so.*remember=(\d+)", content)
        if not match:
            return False, "pam_pwhistory.so satırı bulunamadı."

        current_remember = int(match.group(1))
        if current_remember >= expected_remember:
            return True, f"pam_pwhistory remember={current_remember} (uyumlu ≥{expected_remember})"
        else:
            return False, f"pam_pwhistory remember={current_remember}, beklenen ≥{expected_remember}"

    except Exception as e:
        return False, f"Hata: {e}"


def apply_password_history_remember(username=None, param=None):
    """
    CIS 5.3.3.3.1 - Ensure password history remember is configured
    """
    try:
        remember_val = int(param.get("remember", DEFAULT_REMEMBER)) if param else DEFAULT_REMEMBER

        ok, msg = check_password_reuse({"remember": remember_val})
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        logger.info(f"[apply_password_history_remember] Uyumsuz: {msg} → Düzeltiliyor...")

        profile_content = f"""Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
    requisite pam_pwhistory.so remember={remember_val} enforce_for_root try_first_pass use_authtok
"""

        with open(PAM_PROFILE, "w") as f:
            f.write(profile_content)

        run_command(["pam-auth-update", "--enable", "pwhistory", "--force"])

        logger.info(f"[apply_password_history_remember] pam_pwhistory remember={remember_val} olarak etkinleştirildi.")

        ok, msg = check_password_reuse({"remember": remember_val})
        return ok, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_history_remember] {msg}")
        return False, msg




def check_password_history_enforce_for_root(param=None):
    """
    CIS 5.3.3.3.2 - Ensure password history is enforced for the root user
    """
    try:
        expected_remember = int(param.get("remember", DEFAULT_REMEMBER)) if param else DEFAULT_REMEMBER

        if not os.path.exists(COMMON_PASSWORD):
            return False, f"{COMMON_PASSWORD} bulunamadı."

        with open(COMMON_PASSWORD, "r") as f:
            content = f.read()

        match = re.search(r"pam_pwhistory\.so.*remember=(\d+).*enforce_for_root", content)
        if match:
            current_remember = int(match.group(1))
            if current_remember >= expected_remember:
                return True, f"pam_pwhistory.so enforce_for_root aktif ve remember={current_remember} (uyumlu)"
            else:
                return False, f"remember={current_remember}, beklenen ≥{expected_remember}"
        else:
            return False, "pam_pwhistory.so enforce_for_root bulunamadı."

    except Exception as e:
        return False, f"Hata: {e}"


def apply_password_history_enforce_for_root(username=None, param=None):
    """
    CIS 5.3.3.3.2 - Ensure password history is enforced for the root user
    """
    try:
        remember_val = int(param.get("remember", DEFAULT_REMEMBER)) if param else DEFAULT_REMEMBER

        ok, msg = check_password_history_enforce_for_root({"remember": remember_val})
        if ok:
            logger.info(f"[apply_password_history_enforce_for_root] {msg}")
            return True, msg

        logger.info(f"[apply_password_history_enforce_for_root] Uyumsuz: {msg} → Düzeltiliyor...")

        profile_content = f"""Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
    requisite pam_pwhistory.so remember={remember_val} enforce_for_root try_first_pass use_authtok
"""

        with open(PWHISTORY_PROFILE_PATH, "w") as f:
            f.write(profile_content)

        run_command(["pam-auth-update", "--enable", "pwhistory", "--force"])

        logger.info(f"[apply_password_history_enforce_for_root] enforce_for_root eklendi ve pwhistory etkinleştirildi")

        ok, msg = check_password_history_enforce_for_root({"remember": remember_val})
        return ok, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_history_enforce_for_root] {msg}")
        return False, msg



def check_password_history_use_authtok():
    """
    CIS 5.3.3.3.3 - Ensure pam_pwhistory includes use_authtok
    /etc/pam.d/common-password dosyasında pam_pwhistory.so satırında use_authtok parametresini kontrol eder.
    """

    grep_cmd = ["grep", "-Psi", r"pam_pwhistory\.so.*use_authtok\b", COMMON_PASSWORD]

    success, output = run_command(grep_cmd)

    if success and output.strip():
        return True, "pam_pwhistory.so satırında use_authtok bulundu (uyumlu)"
    else:
        return False, f"{COMMON_PASSWORD} içinde use_authtok bulunamadı"


def apply_password_history_use_authtok(username=None, param=None):
    """
    CIS 5.3.3.3.3 - Ensure pam_pwhistory includes use_authtok
      - /usr/share/pam-configs/pwhistory dosyasını düzenle
      - pam-auth-update --enable pwhistory çalıştır
    """
    compliant, message = check_password_history_use_authtok()
    if compliant:
        logger.info(f"[apply_password_history_use_authtok] {message}")
        return True, message

    logger.info(f"[apply_password_history_use_authtok] Uyumlu değil: {message} → Düzeltiliyor...")

    try:
        remember_val = int(param.get("remember", DEFAULT_REMEMBER)) if param else DEFAULT_REMEMBER

        profile_content = f"""Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
    requisite pam_pwhistory.so remember={remember_val} enforce_for_root try_first_pass use_authtok
"""

        with open(PWHISTORY_PROFILE, "w") as f:
            f.write(profile_content)

        run_command(["pam-auth-update", "--enable", "pwhistory", "--force"])

        final_ok, final_msg = check_password_history_use_authtok()
        if final_ok:
            return True, f"use_authtok eklendi ve doğrulandı ({final_msg})"
        else:
            return False, f"Uygulama sonrası hala uyumsuz: {final_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_history_use_authtok] {msg}")
        return False, msg


COMMON_PAM_FILES = [
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-session",
    "/etc/pam.d/common-session-noninteractive",
]
UNIX_PROFILE = "/usr/share/pam-configs/unix"



def check_pam_unix_nullok():
    """
    CIS 5.3.3.4.1 - Ensure pam_unix does not include nullok
    """
    grep_cmd = [
        "grep", "-PHs",
        r'^\s*[^#\n\r]+\s+pam_unix\.so\s+.*\bnullok\b',
        *COMMON_PAM_FILES
    ]
    success, output = run_command(grep_cmd)

    if success and output.strip():
        return False, f"Uyumsuzluk bulundu: {output.strip()}"
    else:
        return True, "Uyumlu: pam_unix.so satırlarında nullok bulunmuyor."


def apply_pam_unix_nullok(username=None, param=None):
    """
    CIS 5.3.3.4.1 - Ensure pam_unix does not include nullok
      1. /usr/share/pam-configs/unix dosyasından nullok kaldırılır
      2. pam-auth-update --enable unix çağrılır
    """
    compliant, msg = check_pam_unix_nullok()
    if compliant:
        logger.info(f"[apply_pam_unix_nullok] {msg}")
        return True, msg

    logger.info(f"[apply_pam_unix_nullok] Uyumsuz: {msg} → Düzeltiliyor...")

    try:
        if not os.path.exists(UNIX_PROFILE):
            return False, f"{UNIX_PROFILE} bulunamadı."

        with open(UNIX_PROFILE, "r") as f:
            lines = f.readlines()

        new_lines = []
        changed = False
        for line in lines:
            if "pam_unix.so" in line and "nullok" in line and not line.strip().startswith("#"):
                new_line = re.sub(r"\bnullok\b", "", line)
                new_lines.append(new_line)
                changed = True
            else:
                new_lines.append(line)

        if changed:
            with open(UNIX_PROFILE, "w") as f:
                f.writelines(new_lines)

            run_command(["pam-auth-update", "--enable", "unix", "--force"])
            logger.info("[apply_pam_unix_nullok] nullok kaldırıldı ve pam-auth-update çalıştırıldı.")

        final_ok, final_msg = check_pam_unix_nullok()
        if final_ok:
            return True, "nullok kaldırıldı, sistem CIS'e uyumlu hale getirildi."
        else:
            return False, f"Düzeltme sonrası hala uyumsuz: {final_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_pam_unix_nullok] {msg}")
        return False, msg



def check_pam_unix_remember():
    """
    CIS 5.3.3.4.2 - Ensure pam_unix does not include remember
    Hem /etc/pam.d/common-* hem de /usr/share/pam-configs/* altında kontrol eder.
    """
    # 1) /etc/pam.d/common-*
    cmd_common = [
        "grep", "-PHs", "--",
        r'^[[:space:]]*[^#[:space:]]+[[:space:]]+pam_unix\.so.*remember=[0-9]+',
        *COMMON_PAM_FILES
    ]
    ok1, out1 = run_command(cmd_common)
    txt1 = (out1 or "").strip()

    # 2) /usr/share/pam-configs/*
    cmd_profiles = [
        "grep", "-PHs", "--",
        r'^\h*.*pam_unix\.so\h+.*remember=\d+\b',
        "/usr/share/pam-configs/*"
    ]
    ok2, out2 = run_command(cmd_profiles)
    txt2 = (out2 or "").strip()

    if (ok1 and txt1) or (ok2 and txt2):
        details = "\n".join([x for x in [txt1, txt2] if x])
        return False, f"Uyumsuz: pam_unix.so satırlarında remember= bulunuyor:\n{details}"

    return True, "Uyumlu: pam_unix.so için remember= argümanı yok."


def apply_pam_unix_remember(username=None, param=None):
    """
    CIS 5.3.3.4.2 - Ensure pam_unix does not include remember
    - /etc/pam.d/common-* içinden remember=<N> temizlenir
    - /usr/share/pam-configs/* içinden remember=<N> temizlenir
    - 'pam-auth-update --enable unix' ile yeniden oluşturulur
    """
    ok, msg = check_pam_unix_remember()
    if ok:
        return True, f"Zaten uyumlu: {msg}"

    # 1) /etc/pam.d/common-* dosyaları: remember=<N> temizle
    #    Hem "remember=5" hem de boşluk varyasyonlarını yakalayalım.
    fix_common = [
        "bash", "-c",
        r"for f in /etc/pam.d/common-{password,auth,account,session,session-noninteractive}; do "
        r"  if [ -f \"$f\" ]; then "
        r"    sed -i -E 's/\<remember=[0-9]+//g' \"$f\"; "
        r"    sed -i -E 's/[[:space:]]+/ /g' \"$f\"; "  # fazla boşluk temizleme (opsiyonel)
        r"  fi; "
        r"done"
    ]
    ok1, out1 = run_command(fix_common)
    if not ok1:
        return False, f"/etc/pam.d/common-* düzenlenemedi: {out1}"

    # 2) /usr/share/pam-configs/* içinde pam_unix satırlarından remember= kaldır
    fix_profiles = [
        "bash", "-c",
        r"for f in /usr/share/pam-configs/*; do "
        r"  if [ -f \"$f\" ] && grep -qE 'pam_unix\.so' \"$f\"; then "
        r"    sed -i -E 's/\<remember=[0-9]+//g' \"$f\"; "
        r"  fi; "
        r"done"
    ]
    ok2, out2 = run_command(fix_profiles)
    if not ok2:
        return False, f"/usr/share/pam-configs/* düzenlenemedi: {out2}"

    # 3) PAM dosyalarını profilden yeniden üret
    ok3, out3 = run_command(["pam-auth-update", "--enable", "unix", "--force"])
    if not ok3:
        # Bazı sistemlerde --force yok; fallback
        ok3b, out3b = run_command(["pam-auth-update", "--enable", "unix"])
        if not ok3b:
            return False, f"pam-auth-update başarısız: {out3 or out3b}"

    # 4) Son kontrol
    okF, msgF = check_pam_unix_remember()
    if okF:
        return True, "remember argümanı tüm kaynaklardan kaldırıldı ve uyum doğrulandı."
    return False, f"Düzeltme sonrası hala uyumsuz: {msgF}"



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