###############################################################################################################################
###                                                                                                                         ###
###                                             CIS PAM  REVERT                                                             ###
###                                                                                                                         ###
###############################################################################################################################

import os
import re
import shutil

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
    Uyarı: Bu işlem parola tekrar kullanımını yeniden mümkün kılar ve güvenliği azaltır.
    """
    try:
        profile_path = PWHISTORY_PROFILE_PATH
        profile_name = PWHISTORY_PROFILE_NAME

        # pam-auth-update ile devre dışı bırak
        success, output = run_command(["pam-auth-update", "--disable", profile_name])
        if not success:
            logger.error(f"[REVERT] pam-auth-update ile devre dışı bırakma başarısız: {output}")
            return False, f"pam-auth-update çalıştırılamadı: {output}"

        # Profil dosyasını sil (opsiyonel)
        if os.path.exists(profile_path):
            os.remove(profile_path)
            logger.info(f" [CIS 5.3.2.4] [REVERT] PAM profil dosyası silindi: {profile_path}")

        logger.info("[CIS 5.3.2.4 ][REVERT] pam_pwhistory modülü devre dışı bırakıldı.")
        return True, "CIS 5.3.2.4 pam_pwhistory revert edildi, modül devre dışı bırakıldı."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[REVERT] Hata: {msg}")
        return False, f"Revert sırasında hata oluştu: {msg}"


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

        # Orijinal dosyayı geri yükle
        shutil.copy2(backup_path, FAILLOCK_CONF)
        logger.info(f"[CIS 5.3.3.1.1][REVERT] {FAILLOCK_CONF} dosyası yedekten geri yüklendi.")

        return True, f"CIS 5.3.3.1.1 {FAILLOCK_CONF} revert edildi, yedekten geri yüklendi."
    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.1][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"



def revert_unlock_time():
    """
    CIS 5.3.3.1.2 - Revert unlock_time configuration.
    /etc/security/faillock.conf dosyasını yedekten geri yükler.
    """
    try:
        if not os.path.exists(BACKUP_FILE):
            logger.warning("[CIS 5.3.3.1.2][REVERT] Yedek bulunamadı, geri alma yapılamıyor.")
            return False, "Yedek dosya yok, revert gerçekleştirilemedi."

        shutil.copy2(BACKUP_FILE, FAILLOCK_CONF)
        logger.info("[CIS 5.3.3.1.2][REVERT] unlock_time ayarı yedekten geri yüklendi.")

        return True, f"{FAILLOCK_CONF} dosyası revert edildi (unlock_time geri alındı)."
    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.2][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_root_account_lock():
    """
    CIS 5.3.3.1.3 - Revert root account lockout configuration.
    /etc/security/faillock.conf dosyasını yedekten geri yükler.
    """
    try:
        backup_path = FAILLOCK_CONF + ".bak"
        if not os.path.exists(backup_path):
            logger.warning("[CIS 5.3.3.1.3][REVERT] Yedek bulunamadı, geri alma yapılamıyor.")
            return False, "Yedek dosya yok, revert gerçekleştirilemedi."

        shutil.copy2(backup_path, FAILLOCK_CONF)
        logger.info("[CIS 5.3.3.1.3][REVERT] Root account lockout ayarları yedekten geri yüklendi.")

        return True, f"{FAILLOCK_CONF} revert edildi (root_unlock_time ve even_deny_root eski haline döndü)."
    except Exception as e:
        logger.error(f"[CIS 5.3.3.1.3][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_pwquality_difok():
    """
    CIS 5.3.3.2.1 - Revert pwquality difok ayarları
    Debian varsayılanına döner:
      - pwquality.conf içindeki aktif difok satırlarını yorum satırına çevirir (# difok = 2)
      - 50-pwdifok.conf özel dosyasını siler
      - PAM config dizininde difok= parametrelerini temizler
    """
    try:
        if not os.path.exists(PWQUALITY_CONF):
            return False, f"{PWQUALITY_CONF} bulunamadı."

        with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        for line in lines:
            stripped = line.strip()
            if re.match(r'^\s*difok\s*=\s*\d+', stripped) and not stripped.startswith("#"):
                new_lines.append(f"# {stripped}\n")
                modified = True
            else:
                new_lines.append(line)

        if modified:
            with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            logger.info("[CIS 5.3.3.2.1][REVERT] pwquality.conf içindeki aktif difok satırları yorum satırına çevrildi.")
        else:
            logger.info("[CIS 5.3.3.2.1][REVERT] pwquality.conf zaten uygun durumda.")

        if os.path.exists(PWQUALITY_CONF_FILE):
            os.remove(PWQUALITY_CONF_FILE)
            logger.info(f"[CIS 5.3.3.2.1][REVERT] {PWQUALITY_CONF_FILE} silindi.")

        if os.path.isdir(PAM_CONFIG_DIR):
            for root, _, files in os.walk(PAM_CONFIG_DIR):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        if "pam_pwquality.so" in content and "difok=" in content:
                            cleaned = re.sub(r'\bdifok=\d+\b', '', content)
                            with open(fpath, "w", encoding="utf-8") as f:
                                f.write(cleaned)
                            logger.info(f"[CIS 5.3.3.2.1][REVERT] {fpath} içindeki difok= parametresi temizlendi.")
                    except Exception:
                        continue

        return True, "pwquality difok ayarları Debian varsayılanına döndürüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.1][REVERT] {msg}")
        return False, f"Revert hatası: {msg}"


def revert_min_password_length():
    """
    CIS 5.3.3.2.2 - Revert minlen configuration.
    Debian varsayılanına döndürür:
      - pwquality.conf içindeki aktif minlen satırlarını yorum satırına çevirir (# minlen = 8)
      - /etc/security/pwquality.conf.d/50-pwlength.conf dosyasını siler
      - PAM config dosyalarındaki minlen= parametrelerini temizler
    """
    try:
        if not os.path.exists(PWQUALITY_CONF):
            return False, f"{PWQUALITY_CONF} bulunamadı."

        with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        for line in lines:
            stripped = line.strip()
            if re.match(r'^\s*minlen\s*=\s*\d+', stripped) and not stripped.startswith("#"):
                new_lines.append("# minlen = 8\n")  # Debian default
                modified = True
            else:
                new_lines.append(line)

        if modified:
            with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            logger.info("[CIS 5.3.3.2.2][REVERT] pwquality.conf içindeki aktif minlen satırları yorum satırına çevrildi (# minlen = 8).")
        else:
            logger.info("[CIS 5.3.3.2.2][REVERT] pwquality.conf zaten uygun durumda.")

        if os.path.exists(PWQUALITY_FILE):
            os.remove(PWQUALITY_FILE)
            logger.info(f"[CIS 5.3.3.2.2][REVERT] {PWQUALITY_FILE} silindi.")

        if os.path.isdir(PAM_CONFIG_DIR):
            for root, _, files in os.walk(PAM_CONFIG_DIR):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        if "pam_pwquality.so" in content and "minlen=" in content:
                            cleaned = re.sub(r'\bminlen=\d+\b', '', content)
                            with open(fpath, "w", encoding="utf-8") as f:
                                f.write(cleaned)
                            logger.info(f"[CIS 5.3.3.2.2][REVERT] {fpath} içindeki minlen= parametresi temizlendi.")
                    except Exception:
                        continue

        return True, "CIS 5.3.3.2.2 revert tamamlandı: Debian varsayılanı (# minlen = 8) geri yüklendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.2][REVERT] {msg}")
        return False, f"Revert hatası: {msg}"


def revert_pw_complexity():
    """
    CIS 5.3.3.2.3 - Revert password complexity configuration.
    Debian varsayılanına döner:
      - pwquality.conf içindeki aktif minclass/dcredit/ucredit/lcredit/ocredit satırlarını yorumlar (# param = 0)
      - 50-pwcomplexity.conf dosyasını siler
      - PAM config dosyalarındaki bu parametreleri temiz tutar
    """
    try:
        if not os.path.exists(PWQUALITY_CONF):
            return False, f"{PWQUALITY_CONF} bulunamadı."

        keys = ["minclass", "dcredit", "ucredit", "lcredit", "ocredit"]
        with open(PWQUALITY_CONF, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        for line in lines:
            stripped = line.strip()
            if any(re.match(rf"^\s*{k}\s*=", stripped) for k in keys) and not stripped.startswith("#"):
                key = next(k for k in keys if stripped.startswith(k))
                new_lines.append(f"# {key} = 0\n")
                modified = True
            else:
                new_lines.append(line)

        if modified:
            with open(PWQUALITY_CONF, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            logger.info("[CIS 5.3.3.2.3][REVERT] pwquality.conf içindeki aktif karmaşıklık satırları (# param = 0) olarak yorumlandı.")
        else:
            logger.info("[CIS 5.3.3.2.3][REVERT] pwquality.conf zaten uygun durumda.")

        if os.path.exists(PWQUALITY_CONF_D_COMPLEXITY):
            os.remove(PWQUALITY_CONF_D_COMPLEXITY)
            logger.info(f"[CIS 5.3.3.2.3][REVERT] {PWQUALITY_CONF_D_COMPLEXITY} silindi.")

        pam_params = "|".join(keys)
        if os.path.isdir(PAM_CONFIG_DIR):
            for root, _, files in os.walk(PAM_CONFIG_DIR):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        if "pam_pwquality.so" in content and re.search(pam_params, content):
                            cleaned = re.sub(rf'\b({pam_params})\s*=\s*-?\d+\b', '', content)
                            with open(fpath, "w", encoding="utf-8") as f:
                                f.write(cleaned)
                            logger.info(f"[CIS 5.3.3.2.3][REVERT] {fpath} içindeki karmaşıklık parametreleri temizlendi.")
                    except Exception:
                        continue

        return True, "Parola karmaşıklık ayarları Debian varsayılanına geri döndürüldü."

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
    CIS 5.3.3.2.7 - Revert enforcing configuration
    apply_enforcing() işleminin tüm etkilerini geri alır:
      - /etc/security/pwquality.conf.d/50-enforcing.conf dosyasını siler.
      - /etc/security/pwquality.conf ve alt dizinlerde enforcing ile ilgili satırları temizler.
      - /etc/pam.d/common-password ve /usr/share/pam-configs içindeki enforcing parametrelerini kaldırır.
    Sonuç: Sistem Debian varsayılanına döner (enforcing etkin, explicit tanım olmadan).
    """
    try:
        changes = []

        if os.path.exists(ENFORCING_CONF):
            os.remove(ENFORCING_CONF)
            changes.append(f"{ENFORCING_CONF} silindi.")
            logger.info(f"[CIS 5.3.3.2.7][REVERT] {ENFORCING_CONF} dosyası silindi.")

        conf_files = [PWQUALITY_CONF]
        if os.path.isdir(PWQUALITY_DIR):
            for fname in os.listdir(PWQUALITY_DIR):
                if fname.endswith(".conf"):
                    conf_files.append(os.path.join(PWQUALITY_DIR, fname))

        for file in conf_files:
            if os.path.exists(file):
                run_command(["sed", "-ri", r"/^\s*#?\s*enforcing\s*=\s*[0-9]+\b/d", file])
                changes.append(f"{file} içindeki enforcing satırları temizlendi.")
                logger.info(f"[CIS 5.3.3.2.7][REVERT] {file} içindeki enforcing satırları temizlendi.")

        if os.path.exists(COMMON_PASSWORD):
            run_command(["sed", "-ri", r"s/\benforcing\s*=\s*\d+\b//g", COMMON_PASSWORD])
            changes.append("common-password içindeki enforcing parametreleri kaldırıldı.")
            logger.info("[CIS 5.3.3.2.7][REVERT] common-password içindeki enforcing parametreleri kaldırıldı.")

        if os.path.isdir(PAM_CONFIG_DIR):
            for fname in os.listdir(PAM_CONFIG_DIR):
                path = os.path.join(PAM_CONFIG_DIR, fname)
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "r") as f:
                        content = f.read()
                    if "enforcing" in content:
                        run_command(["sed", "-ri", r"s/\benforcing\s*=\s*\d+\b//g", path])
                        changes.append(f"{path} içindeki enforcing parametresi kaldırıldı.")
                        logger.info(f"[CIS 5.3.3.2.7][REVERT] {path} içindeki enforcing parametresi kaldırıldı.")
                except Exception:
                    continue

        msg = f"Revert tamamlandı. {len(changes)} değişiklik yapıldı: {', '.join(changes)}"
        logger.info(f"[CIS 5.3.3.2.7][REVERT] {msg}")
        return True, msg

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
    5.3.3.3.2 - Revert password history enforce_for_root configuration.
    Apply sırasında yapılan remember ve enforce_for_root değişikliklerini kaldırır.
    """
    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        common_password = "/etc/pam.d/common-password"

        if not os.path.exists(profile_path):
            logger.info("[CIS 5.3.3.3.2][REVERT] Profil dosyası bulunamadı, revert gerek yok.")
            return True, "Profil dosyası yok, revert gerek yok."

        with open(profile_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            if "pam_pwhistory.so" in line:
                line = re.sub(r"\benforce_for_root\b", "", line)
                line = re.sub(r"\bremember=\d+\b", "", line)
                line = re.sub(r"\s{2,}", " ", line).strip() + "\n"
            new_lines.append(line)

        with open(profile_path, "w") as f:
            f.writelines(new_lines)

        logger.info("[CIS 5.3.3.3.2][REVERT] enforce_for_root ve remember parametreleri kaldırıldı.")

        success, output = run_command(["pam-auth-update", "--disable", "pwhistory", "--force"])
        if success:
            logger.info("[CIS 5.3.3.3.2][REVERT] pam_pwhistory modülü devre dışı bırakıldı.")
        else:
            logger.warning(f"[CIS 5.3.3.3.2][REVERT] pam-auth-update başarısız: {output}")
            run_command(["sed", "-ri", r"/pam_pwhistory\.so/d", common_password])
            logger.info("[CIS 5.3.3.3.2][REVERT] common-password içinden pam_pwhistory manuel kaldırıldı.")

        return True, "pam_pwhistory enforce_for_root revert edildi (CIS uyumsuz duruma döndü)."

    except Exception as e:
        logger.error(f"[CIS 5.3.3.3.2][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


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
    CIS 5.3.3.4.2 revert
    apply_pam_unix_remember ile kaldırılmış remember=<N> parametresini eski değerine geri alır.
    Param:
        param (dict): {"value": <N>} şeklinde eski değeri alır, yoksa 5 varsayılır.
    """
    old_value = 5

    try:
        logger.info(f"[CIS 5.3.3.4.2][REVERT] remember parametresi eski değere ({old_value}) döndürülüyor...")

        # Düzenlenecek PAM dosyaları
        pam_files = [
            "/etc/pam.d/common-password",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/common-account",
            "/etc/pam.d/common-session",
            "/etc/pam.d/common-session-noninteractive"
        ]

        for file in pam_files:
            if not os.path.exists(file):
                continue


            cmd = [
                "bash", "-c",
                f"if grep -q 'pam_unix.so' '{file}' && ! grep -q 'remember=' '{file}'; "
                f"then sed -i '/pam_unix.so/ s/$/ remember={old_value}/' '{file}'; fi"
            ]
            success, output = run_command(cmd)
            if success:
                logger.info(f"[CIS 5.3.3.4.2][REVERT] {file} güncellendi, remember={old_value} eklendi.")
            else:
                logger.error(f"[CIS 5.3.3.4.2][REVERT] {file} güncellenemedi: {output}")

        return True, f"remember parametresi eski değere ({old_value}) döndürüldü."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.3.3.4.2][REVERT] {msg}")
        return False, msg


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