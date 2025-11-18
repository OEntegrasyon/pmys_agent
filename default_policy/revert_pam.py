###############################################################################################################################
###                                                                                                                         ###
###                                             CIS PAM  REVERT                                                             ###
###                                                                                                                         ###
###############################################################################################################################

import os
import re
import shutil
import glob

from logger import logger
from utils import run_command



PWHISTORY_PROFILE_PATH = "/usr/share/pam-configs/pwhistory"
PWHISTORY_PROFILE_NAME = "pwhistory"
FAILLOCK_CONF = "/etc/security/faillock.conf"
BACKUP_FILE = "/etc/security/faillock.conf.bak"
PWQUALITY_CONF = "/etc/security/pwquality.conf"
PWQUALITY_CONF_DIR = "/etc/security/pwquality.conf.d/"
PWQUALITY_CONF_FILE = f"{PWQUALITY_CONF_DIR}50-pwdifok.conf"
PWQUALITY_FILE = os.path.join(PWQUALITY_CONF_DIR, "50-pwlength.conf")
PWQUALITY_CONF_D_COMPLEXITY = "/etc/security/pwquality.conf.d/50-pwcomplexity.conf"
PWQUALITY_CONF_D_MAXREPEAT  = "/etc/security/pwquality.conf.d/50-pwrepeat.conf"
PWQUALITY_CONF_D_MAXSEQUENCE = "/etc/security/pwquality.conf.d/50-pwmaxsequence.conf"
PWQUALITY_DIR = "/etc/security/pwquality.conf.d"
PWHISTORY_PROFILE = "/usr/share/pam-configs/pwhistory"
COMMON_PASSWORD = "/etc/pam.d/common-password"
PAM_CONFIG_DIR = "/usr/share/pam-configs/"
DICTCHECK_CONF = os.path.join(PWQUALITY_DIR, "50-dictcheck.conf")
ENFORCING_CONF = os.path.join(PWQUALITY_DIR, "50-enforcing.conf")

def revert_libpam_runtime():
    logger.info("[CIS 5.3.1.1][REVERT] libpam-runtime paketinin eski sürüme geçirilmesine gerek yok.")
    pass


def revert_libpam_modules():
    """
    CIS 5.3.1.2 revert. Opsiyonel; normal upgrade kullanıcıları etkilemez.
    """
    logger.info("[CIS 5.3.1.2][REVERT] Revert gerekmez, apt upgrade güvenli.")
    pass

def revert_libpam_pwquality():
    """
    CIS 5.3.1.3 revert. Opsiyonel; kullanıcıyı etkilemez.
    """
    logger.info("[CIS 5.3.1.3][REVERT] Revert gerekli değil, paket kurulumu güvenli.")
    pass

def revert_pam_unix_enabled():
    """
    CIS 5.3.2.1 revert. pam_unix modülü kritik bir modüldür, revert gerekli değil.
    """
    logger.info("[CIS 5.3.2.1][REVERT] Revert gerekli değil; pam_unix devre dışı bırakılmamalı.")
    pass

def revert_pam_faillock():
    """
    CIS 5.3.2.2 revert. pam_faillock modülü güvenlik için kritik, revert yapılmamalı.
    """
    logger.info("[CIS 5.3.2.2][REVERT] Revert gerekli değil; pam_faillock devre dışı bırakılmamalı.")
    pass

def revert_pam_pwquality():
    """
    CIS 5.3.2.3 revert. pam_pwquality modülü kritik, revert yapılmamalı.
    """
    logger.info("[CIS 5.3.2.3][REVERT] Revert gerekli değil; pam_pwquality devre dışı bırakılmamalı.")
    pass


def revert_pwhistory():
    """
    CIS 5.3.2.4 - Revert pam_pwhistory
    Debian varsayılan PAM yapılandırmasına geri döner.
    """
    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        profile_name = "pwhistory"
        target_file = "/etc/pam.d/common-password"

        # pam-auth-update ile disable et
        run_command(["pam-auth-update", "--disable", profile_name])

        # PAM profil dosyasını sil
        if os.path.exists(profile_path):
            os.remove(profile_path)
            logger.info(f"[CIS 5.3.2.4][REVERT] PAM profil silindi: {profile_path}")

        # common-password içindeki pam_pwhistory satırını kaldırır
        if os.path.exists(target_file):
            with open(target_file, "r") as f:
                lines = f.readlines()

            new_lines = [
                line for line in lines
                if "pam_pwhistory.so" not in line  # ilgili satırı hariç bırak
            ]

            with open(target_file, "w") as f:
                f.writelines(new_lines)

            logger.info("[CIS 5.3.2.4][REVERT] common-password içindeki pam_pwhistory satırı kaldırıldı.")

        ok, out = run_command(["grep", "-P", r"pam_pwhistory\.so", target_file])
        if "pam_pwhistory.so" in out:
            return False, "Revert başarısız: pam_pwhistory satırı hala mevcut."

        return True, "pam_pwhistory Debian varsayılanına döndürüldü (revert başarılı)."

    except Exception as e:
        logger.error(f"[REVERT ERROR] {e}")
        return False, f"Revert sırasında hata oluştu: {str(e)}"


DEFAULT_DENY = 5

def revert_failed_attempts_lockout():
    """
    CIS 5.3.3.1.1 - Revert password failed attempts lockout configuration.
    Uyarı: Bu işlem başarısız parola denemesi kilitleme politikasını kaldırır
    ve brute-force riskini artırır.
    """
    try:
        backup_path = FAILLOCK_CONF + ".bak"
        if not os.path.exists(backup_path):
            logger.warning("[REVERT] Yedek bulunamadı, geri alma yapılamıyor.")
            return False, "Yedek dosya yok, revert gerçekleştirilemedi."

        shutil.copy2(backup_path, FAILLOCK_CONF)
        logger.info(f"[CIS 5.3.3.1.1][REVERT] {FAILLOCK_CONF} dosyası yedekten geri yüklendi.")

        return True, f"CIS 5.3.3.1.1 {FAILLOCK_CONF} revert edildi, yedekten geri yüklendi."
    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.1][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


UNLOCK_CONF = "/etc/security/faillock.conf"
FAILLOCK_CONF = "/etc/security/faillock.conf"


def revert_unlock_time():
    """
    CIS 5.3.3.1.2 - Revert
    - /etc/security/faillock.conf içindeki unlock_time satırını SİLER
    - PAM profillerindeki unlock_time= parametresini TEMİZLER
    """

    try:
        # faillock.conf içinden unlock_time satırını kaldır
        if os.path.exists(FAILLOCK_CONF):
            new_lines = []
            with open(FAILLOCK_CONF, "r") as f:
                for line in f:
                    if re.match(r"^\s*unlock_time\s*=", line):
                        continue  # bu satırı atla (sil)
                    new_lines.append(line)

            with open(FAILLOCK_CONF, "w") as f:
                f.writelines(new_lines)

            logger.info("[CIS 5.3.3.1.2][REVERT] unlock_time satırı kaldırıldı (Debian default).")

        # PAM profile dosyalarında unlock_time= geçen parametreyi temizle
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

                logger.info(f"[CIS 5.3.3.1.2][REVERT] PAM profilinde unlock_time kaldırıldı: {fpath}")

            except Exception as e:
                logger.warning(f"[CIS 5.3.3.1.2][REVERT] Dosya işlenemedi: {fpath} → {e}")

        # PAM stack'te common-auth vb dosyalarda unlock_time geçmişse temizle
        for pam_file in ["/etc/pam.d/common-auth", "/etc/pam.d/common-account"]:
            if not os.path.exists(pam_file):
                continue
            lines = []
            changed = False
            with open(pam_file, "r") as f:
                for line in f:
                    if "unlock_time=" in line:
                        cleaned_line = " ".join(x for x in line.split() if not x.startswith("unlock_time="))
                        lines.append(cleaned_line + "\n")
                        changed = True
                    else:
                        lines.append(line)

            if changed:
                with open(pam_file, "w") as f:
                    f.writelines(lines)
                logger.info(f"[CIS 5.3.3.1.2][REVERT] unlock_time parametresi temizlendi: {pam_file}")

        return True, "unlock_time kaldırıldı ve sistem Debian varsayılanına döndürüldü."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.2][REVERT] Hata: {e}")
        return False, str(e)


def revert_root_account_lock(username=None, param=None):
    """
    CIS 5.3.3.1.3 - Geri alma (Debian/Pardus varsayılanına dön)
    - even_deny_root satırını kaldırır
    - root_unlock_time satırını kaldırır
    - PAM içindeki root_unlock_time parametrelerini temizler
    - pam-auth-update kullanılmaz
    """
    try:
        if not os.path.exists(FAILLOCK_CONF):
            return False, f"{FAILLOCK_CONF} mevcut değil, revert gerekmiyor."

        shutil.copy2(FAILLOCK_CONF, FAILLOCK_CONF + ".revert.bak")

        new_lines = []
        changed = False

        with open(FAILLOCK_CONF, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("even_deny_root") or stripped.startswith("root_unlock_time"):
                    changed = True
                    continue
                new_lines.append(line)

        if changed:
            with open(FAILLOCK_CONF, "w") as f:
                f.writelines(new_lines)

        # PAM profillerindeki root_unlock_time parametresini temizle
        ok, files = run_command(["grep", "-Pl", r"pam_faillock\.so.*root_unlock_time", "/usr/share/pam-configs"])
        if ok and files.strip():
            for fpath in files.splitlines():
                try:
                    with open(fpath, "r") as pf:
                        lines = pf.read().splitlines()

                    cleaned = [
                        " ".join(p for p in ln.split() if not p.startswith("root_unlock_time="))
                        for ln in lines
                    ]

                    with open(fpath, "w") as pf:
                        pf.write("\n".join(cleaned) + "\n")
                except Exception:
                    pass

        # common-auth içinde de güvenlik için tekrar temizle
        with open("/etc/pam.d/common-auth", "r") as f:
            lines = f.read().splitlines()

        cleaned = [
            " ".join(p for p in ln.split() if not p.startswith("root_unlock_time="))
            for ln in lines
        ]

        with open("/etc/pam.d/common-auth", "w") as f:
            f.write("\n".join(cleaned) + "\n")

        return True, "Revert tamamlandı: even_deny_root ve root_unlock_time kaldırıldı, sistem varsayılana döndü."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.3][REVERT] {e}")
        return False, f"Revert hatası: {e}"


def revert_pwquality_difok(username=None, param=None):
    """
    Revert for CIS 5.3.3.2.1 difok change:
      - remove PWQUALITY_CONF_FILE if present (backup)
      - uncomment any lines in /etc/security/pwquality.conf that start with '# difok'
        (this attempts to restore previously-commented difok lines)
      - remove difok=... module args from files under /usr/share/pam-configs/
      - make backups (.revert.bak) before editing
    Returns: (True/False, message)
    """
    try:
        actions = []

        if os.path.exists(PWQUALITY_CONF_FILE):
            bak = PWQUALITY_CONF_FILE + ".revert.bak"
            try:
                shutil.copy2(PWQUALITY_CONF_FILE, bak)
                actions.append(f"Yedek alındı: {bak}")
            except Exception as e:
                logger.warning(f"50-pwdifok yedeği alınamadı: {e}")
            try:
                os.remove(PWQUALITY_CONF_FILE)
                actions.append(f"Kaldırıldı: {PWQUALITY_CONF_FILE}")
            except Exception as e:
                return False, f"{PWQUALITY_CONF_FILE} silinirken hata: {e}"

        # PWQUALITY_CONF içindeki '# difok = ...' satırlarını yorumdan çıkar ( ilk eşleşme için)
        if os.path.exists(PWQUALITY_CONF):
            conf_bak = PWQUALITY_CONF + ".revert.bak"
            try:
                shutil.copy2(PWQUALITY_CONF, conf_bak)
                actions.append(f"pwquality.conf yedeği alındı: {conf_bak}")
            except Exception:
                logger.warning("pwquality.conf yedeği alınamadı, devam ediliyor.")

            try:
                with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()

                changed = False
                new_lines = []
                # Eğer apply sırasında sed ile yorumlama yapıldıysa onlar '# difok = ...' şeklinde olacak.
                for ln in lines:
                    m = re.match(r'^\s*#\s*(difok\s*=\s*\d+\b.*)$', ln, flags=re.IGNORECASE)
                    if m:
                        new_ln = re.sub(r'^\s*#\s*', '', ln, count=1)
                        new_lines.append(new_ln)
                        changed = True
                        actions.append(f"pwquality.conf içinde yorumdan çıkarıldı: {new_ln.strip()}")
                    else:
                        new_lines.append(ln)

                if changed:
                    with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                        f.write("\n".join(new_lines) + "\n")
                else:
                    actions.append("pwquality.conf içinde yorumdan çıkarılacak '# difok' bulunmadı.")
            except Exception as e:
                return False, f"pwquality.conf düzenlenirken hata: {e}"
        else:
            actions.append("pwquality.conf bulunmadı; atlandı.")

        # PAM config profillerindeki difok argümanlarını temizle
        pam_files = glob.glob(os.path.join(PAM_CONFIG_DIR, "*"))
        cleaned_any = False
        for fpath in pam_files:
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as pf:
                    content = pf.read()
                if "difok" not in content:
                    continue

                try:
                    shutil.copy2(fpath, fpath + ".revert.bak")
                    actions.append(f"PAM profil yedeği alındı: {fpath}.revert.bak")
                except Exception:
                    logger.warning(f"PAM profil yedeği alınamadı: {fpath}")

                # 'difok = N' veya 'difok=N' veya 'difok= N' gibi argümanları kaldır
                new_lines = []
                for ln in content.splitlines():
                    parts = [p for p in ln.split() if not re.match(r'(?i)^difok\s*=\s*\d+$', p)]
                    new_ln = " ".join(parts)
                    new_lines.append(new_ln)

                with open(fpath, "w", encoding="utf-8") as pf:
                    pf.write("\n".join(new_lines) + "\n")

                cleaned_any = True
                actions.append(f"PAM profil temizlendi: {fpath}")
            except Exception as e:
                logger.warning(f"PAM profil düzenlenemedi: {fpath} -> {e}")
                continue

        if not cleaned_any:
            actions.append("PAM profillerinde temizlenecek difok argümanı bulunmadı.")

        # common-password içinde de difok argümanlarını temizle (yedek al)
        common_password = "/etc/pam.d/common-password"
        if os.path.exists(common_password):
            try:
                shutil.copy2(common_password, common_password + ".revert.bak")
            except Exception:
                logger.warning("common-password yedeği alınamadı.")
            try:
                with open(common_password, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()

                new_lines = []
                changed_cp = False
                for ln in lines:
                    if "pam_pwquality.so" in ln and "difok" in ln:
                        parts = [p for p in ln.split() if not re.match(r'(?i)^difok\s*=\s*\d+$', p)]
                        new_ln = " ".join(parts)
                        new_lines.append(new_ln)
                        changed_cp = True
                    else:
                        new_lines.append(ln)

                if changed_cp:
                    with open(common_password, "w", encoding="utf-8") as f:
                        f.write("\n".join(new_lines) + "\n")
                    actions.append(" /etc/pam.d/common-password içindeki difok argümanları temizlendi.")
                else:
                    actions.append(" /etc/pam.d/common-password içinde difok argümanı bulunmadı.")
            except Exception as e:
                return False, f"common-password düzenlenirken hata: {e}"
        else:
            actions.append("/etc/pam.d/common-password bulunmadı; atlandı.")

        summary = " ; ".join(actions) if actions else "Herhangi bir değişiklik yapılmadı."
        return True, f"Revert tamamlandı. Özet: {summary}"

    except Exception as e:
        logger.exception("[CIS 5.3.3.2.1][pwquality_difok] Hata")
        return False, f"Revert sırasında hata oluştu: {e}"


def revert_min_password_length():
    """
    CIS 5.3.3.2.2 - Revert: minimum parola uzunluğu (minlen) ayarını Debian default haline döndürür.
    - /etc/security/pwquality.conf içindeki minlen satırını siler
    - /etc/security/pwquality.conf.d/ altındaki minlen içeren 50-pw*.conf dosyalarını siler
    - PAM config içinde pam_pwquality.so satırlarından minlen parametresini temizler
    """
    try:

        # Ana pwquality.conf içinden minlen satırını sil
        run_command(["sed", "-ri", "/^\\s*minlen\\s*=/d", PWQUALITY_CONF])

        # .d dizinindeki 50-pw*.conf dosyalarını sil (50-pwlength, 50-pwroot vb hepsi)
        success, files = run_command(["bash", "-c", "ls /etc/security/pwquality.conf.d/50-pw*.conf 2>/dev/null"])
        if success and files:
            for file in files.splitlines():
                run_command(["rm", "-f", file])

        # PAM config içindeki minlen parametrelerini temizle
        success, files = run_command([
            "bash", "-c",
            "grep -Pl '\\bpam_pwquality\\.so\\s+([^#\\n\\r]+\\s+)?minlen\\b' /usr/share/pam-configs/* 2>/dev/null"
        ])

        if success and files.strip():
            for file in files.splitlines():
                run_command(["sed", "-ri", "s/\\bminlen\\s*=\\s*\\d+\\b//g", file])
                logger.info(f"[revert_min_password_length] minlen parametresi temizlendi: {file}")

        logger.info("[CIS 5.3.3.2.2][REVERT] Revert tamamlandı, sistem Debian varsayılanına döndü.")
        return True, "minlen ayarları kaldırıldı, Debian varsayılanına dönüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.2][REVERT] {msg}")
        return False, msg


def revert_pw_complexity():
    """
    CIS 5.3.3.2.3 - Revert password complexity configuration.
    Debian varsayılanına geri döndürür:
      - pwquality.conf içindeki minclass, dcredit, ucredit, lcredit, ocredit satırlarını SİLER
      - pwquality.conf.d/50-pwcomplexity.conf dosyasını SİLER
      - PAM config (pam_pwquality.so) içindeki karmaşıklık override'larını TEMİZLER
      - /etc/pam.d/common-password override'larını da TEMİZLER
    """
    try:
        # pwquality.conf içindeki karmaşıklık satırlarını sil
        if os.path.exists(PWQUALITY_CONF):
            keys = ["minclass", "dcredit", "ucredit", "lcredit", "ocredit"]
            with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
                lines = f.readlines()

            new_lines = []
            modified = False

            for line in lines:
                if any(re.match(rf"^\s*{k}\s*=", line.strip()) for k in keys):
                    modified = True  # atlayarak sil
                    continue
                new_lines.append(line)

            if modified:
                with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                logger.info("[CIS 5.3.3.2.3][REVERT] pwquality.conf içindeki karmaşıklık satırları silindi.")

        # 50-pwcomplexity.conf dosyasını sil
        if os.path.exists(PWQUALITY_CONF_D_COMPLEXITY):
            os.remove(PWQUALITY_CONF_D_COMPLEXITY)
            logger.info(f"[CIS 5.3.3.2.3][REVERT] {PWQUALITY_CONF_D_COMPLEXITY} silindi.")

        # /usr/share/pam-configs içindeki override'ları temizle
        pam_params = r"(minclass|[dulo]credit)"
        if os.path.isdir(PAM_CONFIG_DIR):
            for root, _, files in os.walk(PAM_CONFIG_DIR):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()

                        if "pam_pwquality.so" in content and re.search(pam_params, content):
                            cleaned = re.sub(rf'\b{pam_params}\s*=\s*-?\d+\b', '', content)
                            if cleaned != content:
                                with open(fpath, "w", encoding="utf-8") as f:
                                    f.write(cleaned)
                                logger.info(f"[CIS 5.3.3.2.3][REVERT] {fpath} içindeki karmaşıklık override'ları temizlendi.")
                    except Exception:
                        continue

        # /etc/pam.d/common-password içindeki override'ları temizle
        common_pw = "/etc/pam.d/common-password"
        if os.path.exists(common_pw):
            try:
                with open(common_pw, "r", encoding="utf-8") as f:
                    content = f.read()

                if "pam_pwquality.so" in content and re.search(pam_params, content):
                    cleaned = re.sub(rf'\b{pam_params}\s*=\s*-?\d+\b', '', content)
                    if cleaned != content:
                        with open(common_pw, "w", encoding="utf-8") as f:
                            f.write(cleaned)
                        logger.info("[CIS 5.3.3.2.3][REVERT] common-password içindeki karmaşıklık override'ları temizlendi.")
            except Exception as e:
                logger.error(f"[CIS 5.3.3.2.3][REVERT] common-password temizlenirken hata: {e}")
        logger.info("[CIS 5.3.3.2.3][REVERT] Parola karmaşıklık ayarları tamamen varsayılana döndürüldü.")
        return True, "Parola karmaşıklık ayarları tamamen varsayılana (Debian default) döndürüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.3][REVERT] {msg}")
        return False, f"Revert hatası: {msg}"


def revert_maxrepeat():
    """
    CIS 5.3.3.2.4 - Revert maxrepeat configuration
    İşlev:
      - /etc/security/pwquality.conf.d/50-pwrepeat.conf dosyasını siler.
      - /etc/security/pwquality.conf içindeki aktif maxrepeat satırlarını Debian varsayılanı (# maxrepeat = 0) haline getirir.
    """
    try:
        if os.path.exists(PWQUALITY_CONF):
            with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
                lines = f.readlines()

            new_lines = []
            modified = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("maxrepeat") and not stripped.startswith("#"):
                    new_lines.append("# maxrepeat = 0\n")
                    modified = True
                else:
                    new_lines.append(line)

            if modified:
                with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                logger.info("[CIS 5.3.3.2.4][REVERT] pwquality.conf içindeki aktif maxrepeat satırı (# maxrepeat = 0) haline getirildi.")
            else:
                logger.info("[CIS 5.3.3.2.4][REVERT] pwquality.conf zaten uygun durumda (aktif maxrepeat bulunamadı).")

        if os.path.exists(PWQUALITY_CONF_D_MAXREPEAT):
            os.remove(PWQUALITY_CONF_D_MAXREPEAT)
            logger.info(f"[CIS 5.3.3.2.4][REVERT] {PWQUALITY_CONF_D_MAXREPEAT} dosyası silindi.")
        else:
            logger.info(f"[CIS 5.3.3.2.4][REVERT] {PWQUALITY_CONF_D_MAXREPEAT} zaten mevcut değil.")

        pam_dir = "/usr/share/pam-configs"
        if os.path.isdir(pam_dir):
            for root, _, files in os.walk(pam_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        if "pam_pwquality.so" in content and "maxrepeat" in content:
                            cleaned = re.sub(r"\bmaxrepeat\s*=\s*[0-9]+\b", "", content)
                            with open(fpath, "w", encoding="utf-8") as f:
                                f.write(cleaned)
                            logger.info(f"[CIS 5.3.3.2.4][REVERT] {fpath} içindeki maxrepeat parametreleri temizlendi.")
                    except Exception:
                        continue

        return True, "maxrepeat Debian varsayılanına (yorumlu, # maxrepeat = 0) geri döndürüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.4][REVERT] {msg}")
        return False, f"Revert hatası: {msg}"



def revert_maxsequence():
    """
    CIS 5.3.3.2.5 - Revert
    Yapılan değişiklikleri geri alır:
      - apply sırasında oluşturulan
        /etc/security/pwquality.conf.d/50-pwmaxsequence.conf dosyasını siler.
      - Böylece sistem, pwquality.conf’daki orijinal değerlere döner.

    """
    try:
        conf_file = PWQUALITY_CONF_D_MAXSEQUENCE

        if os.path.exists(conf_file):
            os.remove(conf_file)
            msg = f"{conf_file} silindi, sistem varsayılan maxsequence ayarına döndü."
            logger.info(f"[CIS 5.3.3.2.5][REVERT] {msg}")
            return True, msg
        else:
            msg = f"{conf_file} zaten mevcut değil, revert gereksiz."
            logger.info(f"[CIS 5.3.3.2.5][REVERT] {msg}")
            return True, msg
    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.5][REVERT] {msg}")
        return False, msg


def revert_dictcheck():
    """
    CIS 5.3.3.2.6 - Revert
    apply_dictcheck sırasında yapılan değişiklikleri geri alır:
      - /etc/security/pwquality.conf.d/50-dictcheck.conf dosyasını siler.
      - Böylece sistem varsayılan davranışa (dictcheck etkin) döner.
    """
    try:
        if os.path.exists(DICTCHECK_CONF):
            os.remove(DICTCHECK_CONF)
            msg = f"{DICTCHECK_CONF} silindi, sistem varsayılan dictcheck ayarına döndü (aktif)."
            logger.info(f"[CIS 5.3.3.2.6][REVERT] {msg}")
            return True, msg
        else:
            msg = f"{DICTCHECK_CONF} zaten mevcut değil, revert gereksiz."
            logger.info(f"[CIS 5.3.3.2.6][REVERT] {msg}")
            return True, msg
    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.6][REVERT] {msg}")
        return False, msg


def revert_enforcing():
    """
    CIS 5.3.3.2.7 - Revert enforcing configuration (Debian defaulta döndür)
    - 50-enforcing.conf silinir
    - enforcing=0/1 içeren aktif satırlar temizlenir
    - Sadece pam_pwquality.so içindeki enforcing parametreleri kaldırılır
    """
    try:
        changes = []

        if os.path.exists(ENFORCING_CONF):
            os.remove(ENFORCING_CONF)
            changes.append(f"{ENFORCING_CONF} silindi.")

        # pwquality.conf ve .d içindeki aktif enforcing satırlarını siler
        targets = [PWQUALITY_CONF] + glob.glob(f"{PWQUALITY_DIR}/*.conf")
        for conf in targets:
            if os.path.isfile(conf):
                run_command(["sed", "-ri", r"/^\s*enforcing\s*=\s*[0-9]+\b/d", conf])
                changes.append(f"{conf} içindeki enforcing tanımları silindi.")

        # common-password içinde sadece pam_pwquality.so satırındaki enforcing parametrelerini kaldırır
        if os.path.isfile(COMMON_PASSWORD):
            run_command([
                "sed", "-ri",
                r"s/(pam_pwquality\.so[^#\n\r]*?)\benforcing\s*=\s*\d+(\s*|$)/\1\2/g",
                COMMON_PASSWORD
            ])
            changes.append("common-password pam_pwquality enforcing temizlendi.")

        # pam-configs içinde sadece pam_pwquality.so satırlarındaki enforcing’i kaldırır
        grep_cmd = ["grep", "-Pl", r"pam_pwquality\.so.*enforcing", f"{PAM_CONFIG_DIR}/*"]
        ok, out = run_command(grep_cmd)

        if ok and out.strip():
            for f in out.splitlines():
                run_command([
                    "sed", "-ri",
                    r"s/(pam_pwquality\.so[^#\n\r]*?)\benforcing\s*=\s*\d+(\s*|$)/\1\2/g",
                    f
                ])
                changes.append(f"{f} pam_pwquality enforcing temizlendi.")
        logger.info(f"[CIS 5.3.3.2.7][REVERT] Revert tamamlandı ({len(changes)} değişiklik): " + ", ".join(changes))
        return True, f"Revert tamamlandı ({len(changes)} değişiklik): " + ", ".join(changes)

    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.7][REVERT] {msg}")
        return False, msg


def revert_enforce_for_root():
    """
    CIS 5.3.3.2.8 - Revert
    'apply_enforce_for_root()' tarafından yapılan değişiklikleri geri alır.

    Geri alma işlemi şunları yapar:
      - /etc/security/pwquality.conf.d/50-pwroot.conf dosyasını siler.
      - /etc/security/pwquality.conf ve .d altındaki enforcing satırlarını temizler.
      - Böylece sistem Debian varsayılanına döner (root için enforce zorunluluğu kalkar).
    """
    conf_main = "/etc/security/pwquality.conf"
    conf_dir = "/etc/security/pwquality.conf.d"
    pwroot_file = os.path.join(conf_dir, "50-pwroot.conf")

    try:
        changes = []

        if os.path.exists(pwroot_file):
            os.remove(pwroot_file)
            changes.append(f"{pwroot_file} silindi (özel enforce_for_root dosyası).")

        target_files = [conf_main]
        if os.path.isdir(conf_dir):
            for f in os.listdir(conf_dir):
                if f.endswith(".conf"):
                    target_files.append(os.path.join(conf_dir, f))

        for fpath in target_files:
            if not os.path.exists(fpath):
                continue
            try:
                run_command(["sed", "-ri", r"/^\s*#?\s*enforce_for_root\b/d", fpath])
                changes.append(f"{fpath} içindeki enforce_for_root satırları temizlendi.")
            except Exception as e:
                logger.warning(f"[CIS 5.3.3.2.8][REVERT] {fpath} düzenlenemedi: {e}")

        if changes:
            summary = " | ".join(changes)
            logger.info(f"[CIS 5.3.3.2.8][REVERT] Revert tamamlandı. {len(changes)} değişiklik yapıldı: {summary}")
            return True, f"Revert tamamlandı. {len(changes)} değişiklik yapıldı."
        else:
            logger.info("[CIS 5.3.3.2.8][REVERT] Yapılacak değişiklik bulunamadı (zaten varsayılanda).")
            return True, "Sistem zaten varsayılanda (enforce_for_root tanımı yok)."

    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.8][REVERT] {msg}")
        return False, msg


def revert_password_history_remember():
    """
    CIS 5.3.3.3.1 - Revert password history remember configuration.
    'apply_password_history_remember()' tarafından yapılan değişiklikleri geri alır.

    Geri alma işlemi:
      - /usr/share/pam-configs/pwhistory dosyasını siler.
      - pam-auth-update ile pwhistory profilini devre dışı bırakır.
      - Gerekirse /etc/pam.d/common-password içinden pam_pwhistory.so satırını manuel temizler.
    """
    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        common_password = "/etc/pam.d/common-password"

        if os.path.exists(profile_path):
            os.remove(profile_path)
            logger.info("[CIS 5.3.3.3.1][REVERT] pwhistory profili kaldırıldı.")
        else:
            logger.info("[CIS 5.3.3.3.1][REVERT] pwhistory profili zaten mevcut değildi.")

        success, output = run_command([
            "pam-auth-update", "--disable", "pwhistory", "--force"
        ])
        if success:
            logger.info("[CIS 5.3.3.3.1][REVERT] pam_pwhistory modülü devre dışı bırakıldı.")
        else:
            logger.warning(f"[CIS 5.3.3.3.1][REVERT] pam-auth-update başarısız: {output}")

            if os.path.exists(common_password):
                run_command(["sed", "-ri", r"/pam_pwhistory\.so/d", common_password])
                logger.info("[CIS 5.3.3.3.1][REVERT] common-password içinden pam_pwhistory.so manuel kaldırıldı.")

        success, _ = run_command(["grep", "-q", "pam_pwhistory.so", common_password])
        if success:
            return False, "pam_pwhistory hala etkin görünüyor (manuel kontrol gerekebilir)."
        else:
            return True, "pam_pwhistory revert edildi (devre dışı, CIS uyumsuz duruma döndü)."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.3.1][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_password_history_enforce_for_root():
    """
    CIS 5.3.3.3.2 - Revert password history enforce_for_root configuration.
    'apply_password_history_enforce_for_root' işlemini geri alır:
      - /usr/share/pam-configs/pwhistory dosyasını siler veya temizler.
      - pam_pwhistory modülünü devre dışı bırakır.
      - common-password içindeki enforce_for_root ve remember parametrelerini kaldırır.
    """
    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        common_password = "/etc/pam.d/common-password"

        # Profil dosyasını kaldır veya temizle
        if os.path.exists(profile_path):
            os.remove(profile_path)
            logger.info("[CIS 5.3.3.3.2][REVERT] pwhistory profili silindi.")
        else:
            logger.info("[CIS 5.3.3.3.2][REVERT] Profil zaten mevcut değil.")

        # PAM modülünü devre dışı bırakır
        success, output = run_command(["pam-auth-update", "--disable", "pwhistory", "--force"])
        if success:
            logger.info("[CIS 5.3.3.3.2][REVERT] pam_pwhistory modülü devre dışı bırakıldı.")
        else:
            logger.warning(f"[CIS 5.3.3.3.2][REVERT] pam-auth-update başarısız: {output}")

        # common-password dosyasında parametre temizliği
        if os.path.exists(common_password):
            run_command(["sed", "-ri", r"s/\benforce_for_root\b//g", common_password])
            run_command(["sed", "-ri", r"s/\bremember=\d+\b//g", common_password])
            logger.info("[CIS 5.3.3.3.2][REVERT] common-password içindeki enforce_for_root ve remember parametreleri kaldırıldı.")

        return True, "pam_pwhistory enforce_for_root ayarları geri alındı (CIS 5.3.3.3.2 revert tamamlandı)."

    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.3.2][REVERT] {msg}")
        return False, f"Revert sırasında hata: {msg}"


def revert_password_history_use_authtok():
    """
    5.3.3.3.3 - Revert: pam_pwhistory.so satırındaki use_authtok parametresini kaldırır.
    Ayrıca /usr/share/pam-configs/pwhistory dosyasında da temizler.
    """
    try:
        modified_files = []
        common_password = "/etc/pam.d/common-password"
        pwhistory_profile = "/usr/share/pam-configs/pwhistory"

        if os.path.exists(common_password):
            with open(common_password, "r") as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if "pam_pwhistory.so" in line:
                    line = re.sub(r"\buse_authtok\b", "", line)
                    line = re.sub(r"\s{2,}", " ", line).strip() + "\n"
                new_lines.append(line)

            with open(common_password, "w") as f:
                f.writelines(new_lines)
            modified_files.append(common_password)
            logger.info("[CIS 5.3.3.3.3][REVERT] common-password içindeki use_authtok kaldırıldı.")

        if os.path.exists(pwhistory_profile):
            with open(pwhistory_profile, "r") as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if "pam_pwhistory.so" in line:
                    line = re.sub(r"\buse_authtok\b", "", line)
                    line = re.sub(r"\s{2,}", " ", line).strip() + "\n"
                new_lines.append(line)

            with open(pwhistory_profile, "w") as f:
                f.writelines(new_lines)
            modified_files.append(pwhistory_profile)
            logger.info("[CIS 5.3.3.3.3][REVERT] pwhistory profilindeki use_authtok kaldırıldı.")

        success, output = run_command([
            "bash", "-c", "DEBIAN_FRONTEND=noninteractive pam-auth-update --force"
        ])
        if success:
            logger.info("[CIS 5.3.3.3.3][REVERT] PAM yapılandırması güncellendi (non-interactive).")
        else:
            logger.warning(f"[CIS 5.3.3.3.3][REVERT] pam-auth-update başarısız: {output}")

        if modified_files:
            return True, f"use_authtok parametresi kaldırıldı ({', '.join(modified_files)})"
        else:
            return True, "use_authtok bulunamadı, revert gerek yok."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.3.3][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_pam_unix_nullok():
    """
    CIS 5.3.3.4.1 revert. pam_pwquality modülü kritik, revert yapılmamalı.
    """
    logger.info("[CIS 5.3.3.4.1][REVERT] Revert gerekli değil; pam_pwquality devre dışı bırakılmamalı.")
    pass


def revert_pam_unix_remember():
    """
    CIS 5.3.3.4.2 revert.
    """
    logger.info("[CIS 5.3.3.4.2][REVERT] Revert gerekli değil;")
    pass


def revert_pam_unix_strong_hash():
    """
    CIS 5.3.3.4.3 revert.
    """
    logger.info("[CIS 5.3.3.4.3][REVERT] Revert gerekli değil.")
    pass



def revert_pam_unix_use_authtok():
    """
    CIS 5.3.3.4.4 revert.
    """
    logger.info("[CIS 5.3.3.4.4][REVERT] Revert gerekli değil.")
    pass



###############  CIS HARICI POLITIKA REVERTLERI  #####################



def revert_pam_faillock():
    """
    Reverts failed login attempts lockout and central logging mechanism.
    (pam_faillock modülünü devre dışı bırakır.)
    
    Uyarı: Bu işlem kaba kuvvet saldırılarına karşı korumayı ve merkezi loglamayı azaltır.
    """
    PROFILE_NAME = "faillock"
    
    logger.info(f"[PAM Faillock][REVERT] Geri alma başlatıldı: '{PROFILE_NAME}' profili devre dışı bırakılıyor.")

    try:
        # pam-auth-update aracılığıyla faillock profilini devre dışı bırak
        success_update, output_update = run_command(["pam-auth-update", "--disable", PROFILE_NAME])
        
        if not success_update:
            msg = f"pam-auth-update ile '{PROFILE_NAME}' devre dışı bırakılamadı: {output_update}"
            logger.error(f"[PAM Faillock][REVERT] HATA: {msg}")
            return False, msg

        # Not: pam-auth-update, yapılandırmayı otomatik olarak yeniden yükler.
        
        logger.info("[PAM Faillock][REVERT] Faillock profili başarıyla devre dışı bırakıldı.")
        return True, f"CIS 5.3.3.x faillock profili başarıyla revert edildi. Hesap kilitleme politikası kaldırıldı."

    except Exception as e:
        msg = f"Geri alma sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[PAM Faillock][REVERT] HATA: {msg}")
        return False, f"Revert sırasında hata oluştu: {msg}"