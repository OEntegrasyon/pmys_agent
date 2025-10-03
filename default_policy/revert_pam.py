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
PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d/50-pwcomplexity.conf"
PWHISTORY_PROFILE = "/usr/share/pam-configs/pwhistory"
COMMON_PASSWORD = "/etc/pam.d/common-password"



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
    CIS 5.3.3.2.1 revert metodu.
    Uygulanan difok ayarlarını geri alır.
    """
    try:
        backup_file = PWQUALITY_CONF + ".bak"

        # Eğer yedek varsa geri yükle
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, PWQUALITY_CONF)
            logger.info("[CIS 5.3.3.2.1][REVERT] pwquality.conf yedekten geri yüklendi.")

        # Uygulama sırasında oluşturulan özel dosyayı sil
        if os.path.exists(PWQUALITY_CONF_FILE):
            os.remove(PWQUALITY_CONF_FILE)
            logger.info(f"[CIS 5.3.3.2.1][REVERT] {PWQUALITY_CONF_FILE} silindi.")
        logger.info(f"[CIS 5.3.3.2.1][REVERT] pwquality difok ayarları geri alındı.")
        return True, "pwquality difok ayarları geri alındı."
    except Exception as e:
        msg = f"Revert hatası: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.1][REVERT] {msg}")
        return False, msg


def revert_min_password_length():
    """
    CIS 5.3.3.2.2 revert metodu.
    Uygulanan minlen ayarlarını geri alır.
    """
    try:
        backup_file = PWQUALITY_CONF + ".bak"

        # Eğer yedek varsa geri yükle
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, PWQUALITY_CONF)
            logger.info("[CIS 5.3.3.2.2][REVERT] pwquality.conf yedekten geri yüklendi.")

        # apply sırasında oluşturulan özel dosyayı sil
        if os.path.exists(PWQUALITY_FILE):
            os.remove(PWQUALITY_FILE)
            logger.info(f"[CIS 5.3.3.2.2][REVERT] {PWQUALITY_FILE} silindi.")

        logger.info(f"[CIS 5.3.3.2.2][REVERT] minlen ayarları geri alındı.")
        return True, "minlen ayarları geri alındı."
    except Exception as e:
        msg = f"Revert hatası: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.2][REVERT] {msg}")
        return False, msg


def revert_pw_complexity():
    """
    CIS 5.3.3.2.3 revert metodu.
    Parola karmaşıklık ayarlarını geri alır.
    """
    try:
        backup_file = PWQUALITY_CONF + ".bak"

        # Yedek varsa geri yükle
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, PWQUALITY_CONF)
            logger.info("[CIS 5.3.3.2.3][REVERT] pwquality.conf yedekten geri yüklendi.")

        # complexity için oluşturulan .d dosyası sil
        if os.path.exists(PWQUALITY_CONF_D):
            os.remove(PWQUALITY_CONF_D)
            logger.info(f"[CIS 5.3.3.2.3][REVERT] {PWQUALITY_CONF_D} silindi.")
        logger.info(f"[CIS 5.3.3.2.3][REVERT] Parola karmaşıklık ayarları geri alındı.")
        return True, "Parola karmaşıklık ayarları geri alındı."
    except Exception as e:
        msg = f"Revert hatası: {str(e)}"
        logger.error(f"[CIS 5.3.3.2.3][REVERT] {msg}")
        return False, msg


def revert_maxrepeat():
    """
    CIS 5.3.3.2.4 - Ensure password same consecutive characters is configured
    Revert işlemi:
      - apply sırasında oluşturulan /etc/security/pwquality.conf.d/50-pwrepeat.conf dosyası silinir.
      - Böylece sistem default değerlere döner.
    Returns:
        (bool, str): (Başarılı mı?, Mesaj)
    """
    try:
        if os.path.exists(PWQUALITY_CONF_D):
            os.remove(PWQUALITY_CONF_D)
            msg = f"{PWQUALITY_CONF_D} dosyası silindi. Default değerlere dönüldü."
            logger.info(f"[CIS 5.3.3.2.4][REVERT] {msg}")
            return True, msg
        else:
            msg = f"{PWQUALITY_CONF_D} zaten mevcut değil, revert gereksiz."
            logger.info(f"[CIS 5.3.3.2.4][REVERT] {msg}")
            return True, msg
    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.4][REVERT] {msg}")
        return False, msg

def revert_maxsequence():
    """
    CIS 5.3.3.2.5 - Revert
    Yapılan değişiklikleri geri alır:
      - apply sırasında oluşturulan
        /etc/security/pwquality.conf.d/50-pwmaxsequence.conf dosyasını siler.
      - Böylece sistem, pwquality.conf’daki orijinal değerlere döner.

    """
    conf_file = "/etc/security/pwquality.conf.d/50-pwmaxsequence.conf"
    try:
        if os.path.exists(conf_file):
            os.remove(conf_file)
            msg = f"{conf_file} silindi, sistem varsayılan maxsequence ayarına döndü."
            logger.info(f"[CIS 5.3.3.2.5][REVERT] {msg}")
            return True, msg
        else:
            msg = f"{conf_file} zaten yok, revert gereksiz."
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

    Returns:
        (bool, str): (Başarılı mı?, Mesaj)
    """
    conf_file = "/etc/security/pwquality.conf.d/50-dictcheck.conf"
    try:
        if os.path.exists(conf_file):
            os.remove(conf_file)
            msg = f"{conf_file} silindi, sistem varsayılan dictcheck ayarına döndü."
            logger.info(f"[CIS 5.3.3.2.6][REVERT] {msg}")
            return True, msg
        else:
            msg = f"{conf_file} zaten yok, revert gereksiz."
            logger.info(f"[CIS 5.3.3.2.6][REVERT] {msg}")
            return True, msg
    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.3.3.2.6][REVERT] {msg}")
        return False, msg


def revert_enforcing():
    """
    CIS 5.3.3.2.7 - enforcing ayarı için revert gereksizdir.
    Güvenlik gereği enforcing=1 zorunlu kalmalıdır.
    """
    logger.info("[CIS 5.3.3.2.7][REVERT] Revert uygulanmadı (CIS gereği enforcing zorunludur).")
    pass


def revert_enforce_for_root():
    """
    5.3.3.2.8 - enforce_for_root ayarı için revert gerekmez.
    Güvenlik gereği enforce_for_root aktif kalmalıdır.
    """
    logger.info("[CIS 5.3.3.2.8][REVERT] Revert uygulanmadı (CIS gereği enforce_for_root zorunludur).")
    pass


def revert_password_history_remember():
    """
    5.3.3.3.1 - Password history remember revert işlemi
    """
    try:
        profile_path = "/usr/share/pam-configs/pwhistory"
        if os.path.exists(profile_path):
            os.remove(profile_path)
            logger.info("[CIS 5.3.3.3.1][REVERT] pwhistory profili kaldırıldı.")

        success, output = run_command([
            "pam-auth-update", "--disable", "pwhistory", "--force"
        ])
        if success:
            logger.info("[CIS 5.3.3.3.1][REVERT] pam_pwhistory devre dışı bırakıldı.")
            return True, "pam_pwhistory revert edildi (CIS uyumsuz)."
        else:
            logger.error(f"[CIS 5.3.3.3.1][REVERT] Komut hatası: {output}")
            return False, f"pam_pwhistory revert edilemedi: {output}"

    except Exception as e:
        logger.error(f"[CIS 5.3.3.3.1][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_password_history_enforce_for_root():
    """
    5.3.3.3.2 revert: enforce_for_root ve remember parametrelerini kaldırır.

    """
    try:
        if not os.path.exists(PWHISTORY_PROFILE):
            logger.info("[CIS 5.3.3.3.2][REVERT] Profil dosyası bulunamadı, revert gerek yok.")
            return True, "Profil dosyası yok, revert gerek yok."

        with open(PWHISTORY_PROFILE, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:

            if "pam_pwhistory.so" in line:
                line = re.sub(r"\benforce_for_root\b", "", line)
                line = re.sub(r"\bremember=\d+\b", "", line)
                line = re.sub(r"\s{2,}", " ", line).strip() + "\n"
            new_lines.append(line)

        with open(PWHISTORY_PROFILE, "w") as f:
            f.writelines(new_lines)

        success, output = run_command(["pam-auth-update", "--disable", "pwhistory", "--force"])
        if success:
            logger.info("[CIS 5.3.3.3.2][REVERT] pam_pwhistory revert edildi")
            return True, "pam_pwhistory revert edildi (CIS uyumsuz)"
        else:
            logger.error(f"[CIS 5.3.3.3.2][REVERT] Komut hatası: {output}")
            return False, f"pam_pwhistory revert edilemedi: {output}"

    except Exception as e:
        logger.error(f"[CIS 5.3.3.3.2][REVERT] Hata: {e}")
        return False, f"Revert sırasında hata: {e}"


def revert_password_history_use_authtok():
    """
    5.3.3.3.3 revert: pam_pwhistory.so satırındaki use_authtok parametresini kaldırır.
    """
    try:
        if not os.path.exists(COMMON_PASSWORD):
            logger.info("[CIS 5.3.3.3.3 ][REVERT] Dosya bulunamadı, revert gerek yok.")
            return True, "Dosya yok, revert gerek yok."

        with open(COMMON_PASSWORD, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            if re.search(r"pam_pwhistory\.so", line):
                line = re.sub(r"\buse_authtok\b", "", line)
                line = re.sub(r"\s{2,}", " ", line).strip() + "\n"
            new_lines.append(line)

        with open(COMMON_PASSWORD, "w") as f:
            f.writelines(new_lines)

        logger.info("[CIS 5.3.3.3.3][REVERT] use_authtok parametresi kaldırıldı")
        return True, "pam_pwhistory.so use_authtok revert edildi (CIS uyumsuz)"
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