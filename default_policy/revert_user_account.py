###############################################################################################################################
###                                                                                                                         ###
###                                             CIS 5.4 User Accounts and Environment Revert                                ###
###                                                                                                                         ###
###############################################################################################################################

import os
import re

from logger import logger
from utils import run_command


def revert_password_expiration():
    """
    CIS 5.4.1.1 - Revert
    /etc/login.defs dosyasını son yedekten geri yükler
    ve kullanıcıların PASS_MAX_DAYS ayarlarını eski haline döndürür.
    """
    try:
        login_defs = "/etc/login.defs"

        # Son oluşturulmuş .bak dosyasını bul
        bak_files = sorted(
            [f for f in os.listdir("/etc") if f.startswith("login.defs.bak_")],
            reverse=True
        )
        if not bak_files:
            logger.warning("[CIS 5.4.1.1][REVERT] Geri yükleme için yedek bulunamadı.")
            return False, "Yedek bulunamadı"

        last_backup = f"/etc/{bak_files[0]}"

        # Mevcut dosyayı kaldır, yedeği geri yükle
        os.remove(login_defs)
        os.rename(last_backup, login_defs)
        logger.info(f"[CIS 5.4.1.1][REVERT] {login_defs} dosyası {last_backup} yedeğinden geri yüklendi.")

        # Kullanıcıların ayarlarını geri almak pratikte mümkün değil
        # çünkü `chage` ile yapılan değişikliklerin eski değeri saklanmıyor.
        # Sadece login.defs revert edilir.
        logger.warning("[CIS 5.4.1.1] Kullanıcı bazlı PASS_MAX_DAYS geri alınamıyor. "
                       "Sadece login.defs geri yüklendi.")

        return True, f"{login_defs} yedekten geri yüklendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[REVERT] {msg}")
        return False, msg



def revert_min_password_days(username=None, param=None):
    """
    CIS 5.4.1.2 Minimum Password Days
    Revert için özel: PASS_MIN_DAYS değerini 1 güne ayarlar.
    Kullanıcıların min_days değerlerini de chage ile 1 yapar.
    """
    try:
        revert_value = int(param.get("value", 1)) if param else 1

        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            return False, "/etc/login.defs bulunamadı"


        new_lines = []
        found = False
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                if re.match(r'^\s*#', line) or line.strip() == "":
                    new_lines.append(line)
                    continue
                m = re.match(r'^\s*PASS_MIN_DAYS\s+(\d+)\b', line)
                if m:
                    new_lines.append(f"PASS_MIN_DAYS   {revert_value}\n")
                    found = True
                else:
                    new_lines.append(line)

        if not found:
            new_lines.append(f"\nPASS_MIN_DAYS   {revert_value}\n")

        tmp_path = f"{login_defs}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        os.replace(tmp_path, login_defs)
        logger.info(f"[CIS 5.4.1.2][REVERT] /etc/login.defs PASS_MIN_DAYS {revert_value} olarak güncellendi")


        shadow = "/etc/shadow"
        if os.path.exists(shadow):
            with open(shadow, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.rstrip("\n").split(":")
                    if len(parts) < 5:
                        continue
                    user = parts[0]
                    passwd_field = parts[1]
                    if passwd_field and passwd_field.startswith("$"):
                        rc, out = run_command(["chage", "--mindays", str(revert_value), user])
                        if not rc:
                            logger.warning(f"[CIS 5.4.1.2][REVERT] {user} için revert başarısız: {out}")
                        else:
                            logger.info(f"[CIS 5.4.1.2][REVERT] {user} için mindays={revert_value} olarak ayarlandı")

        return True, f"PASS_MIN_DAYS {revert_value} gün olarak revert edildi"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.4.1.2][REVERT] Hata: {msg}")
        return False, msg



def revert_password_warn_days(username=None, param=None):
    """
    CIS 5.4.1.3 - Password Warning Days
    PASS_WARN_AGE değerini geri alır.
    Varsayılan: 120 gün olarak ayarlar.
    """
    try:
        revert_value = int(param.get("revert_value", 120)) if param else 120

        # login.defs revert
        with open("/etc/login.defs", "r") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if re.search(r"^\s*PASS_WARN_AGE\s+", line) and not line.strip().startswith("#"):
                new_lines.append(f"PASS_WARN_AGE {revert_value}\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(f"PASS_WARN_AGE {revert_value}\n")

        with open("/etc/login.defs", "w") as f:
            f.writelines(new_lines)

        # shadow revert
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    user = parts[0]
                    passwd_field = parts[1]

                    # sadece parola set edilmiş ve root olmayan kullanıcılar
                    if passwd_field.startswith("$") and user != "root":
                        success, out = run_command(["chage", "--warndays", str(revert_value), user])
                        if success:
                            logger.info(f"[CIS 5.4.1.3][REVERT] {user} için PASS_WARN_AGE revert edildi -> {revert_value} : {out}")
                        else:
                            logger.error(f"[CIS 5.4.1.3][REVERT] {user} revert başarısız: {out}")
        logger.info(f"[CIS 5.4.1.3][REVERT] işlemi tamamlandı.")
        return True, f"[CIS 5.4.1.3][REVERT] işlemi tamamlandı. ({revert_value})"

    except Exception as e:
        logger.error(f"[CIS 5.4.1.3][REVERT] işlemi hatası: {str(e)}")
        return False, f"[CIS 5.4.1.3][REVERT] işlemi hatası: {str(e)}"


def revert_password_hashing_algorithm():
    """
    CIS 5.4.1.4 - Password Hashing Algorithm
    Revert mantıklı değildir, çünkü eski algoritmaya dönmek güvenliği zayıflatır.
    Bu nedenle burada işlem yapılmaz.
    """
    logger.info("[CIS 5.4.1.4][REVERT] Revert uygulanmadı (güvenlik sebebiyle).")
    pass



def revert_inactive_password_lock(username=None, param=None):
    """
    CIS 5.4.1.5
    INACTIVE değerini revert eder.
    Varsayılan revert değeri: 99999 gün (sınırsıza yakın).
    """
    try:
        revert_days = (param or {}).get("revert_days", 99999)

        # Yeni kullanıcılar için default revert
        run_command(["useradd", "-D", "-f", str(revert_days)])

        # Mevcut kullanıcılar için revert
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 8:
                    continue
                user, passwd = parts[0], parts[1]
                if not passwd.startswith("$"):  # sadece şifreli hesaplar
                    continue
                run_command(["chage", "--inactive", str(revert_days), user])

        logger.info(f"[CIS 5.4.1.5][REVERT] INACTIVE {revert_days} gün olarak revert edildi.")
        return True, f"INACTIVE revert edildi -> {revert_days} gün"

    except Exception as e:
        logger.error(f"[CIS 5.4.1.5][REVERT] Hata: {e}")
        return False, str(e)


def revert_last_password_change_in_past():
    """
    CIS 5.4.1.6 revert:
    Bu madde için geri alma (revert) uygulanmaz.
    Çünkü uygunsuz durum gelecekte parola tarihi atamak olur ki
    bu güvenlik açığına yol açar.
    """
    logger.info("[CIS 5.4.1.6][REVERT]  (skip).")
    pass


def revert_only_root_uid0():
    """
    CIS 5.4.2.1 revert:
    Geri alma işlemi uygulanmaz çünkü UID 0 sadece root’a ait olmalıdır.
    Başka kullanıcıya geri UID 0 atamak CIS uyumunu bozar ve güvenlik açığı oluşturur.
    """
    logger.info("[CIS 5.4.2.1][REVERT] (skip).")
    pass


def revert_only_root_gid0():
    """
    CIS 5.4.2.2 revert:
    Geri alma işlemi uygulanmaz çünkü root dışındaki kullanıcılara GID 0 vermek
    CIS uyumunu bozar ve güvenlik açığı oluşturur.
    """
    logger.info("[CIS 5.4.2.2][REVERT] (skip).")
    pass


def revert_only_root_group_gid0():
    """
    CIS 5.4.2.3 revert:
    Geri alma işlemi uygulanmaz çünkü root dışındaki gruplara GID 0 vermek
    CIS uyumunu bozar ve güvenlik açığı oluşturur.
    """
    logger.info("[CIS 5.4.2.3][REVERT] (skip).")
    pass


def revert_root_account_access():
    """
    5.4.2.4 Ensure root account access is controlled (Revert)
    Açıklama:
        CIS bu maddenin geri alınmasını öngörmez.
        Root hesabının kontrolsüz bırakılması güvenlik riski oluşturur.
        Bu nedenle geri alma işlemi uygulanmaz.
    """
    logger.info("[CIS 5.4.2.4][REVERT] (skip).")
    pass


def revert_root_path_integrity():
    """
    5.4.2.5 - Revert root PATH integrity changes.
    Açıklama:
        CIS standardı root PATH'in tehlikeli olacak şekilde geri alınmasını öngörmez.
        Bu nedenle revert işlemi uygulanmaz.
    """
    logger.info("[CIS 5.4.2.5][REVERT] (skip).")
    pass


def revert_root_umask():
    """
    5.4.2.6 - Revert root umask ayarı.
    Açıklama:
        CIS standardı root umask'in daha gevşek hale getirilmesini öngörmez.
        Bu nedenle revert işlemi uygulanmaz.
    """
    logger.info("[CIS 5.4.2.6][REVERT] (skip).")
    pass



def revert_system_accounts_shell():
    """
    5.4.2.7 Bu ayar için geri alma uygulanmaz.
    CIS standardına göre sistem hesaplarının login shell'i 
    tekrar aktif hale getirilmemelidir.
    """
    logger.info("[CIS 5.4.2.7][REVERT] (skip).")
    pass


def revert_accounts_without_login_shell_locked():
    """
    [REVERT][5.4.2.8] Bu ayar için geri alma uygulanmaz.
    CIS standardına göre login shell'i olmayan hesaplar tekrar açılmamalıdır.
    """
    logger.info("[CIS 5.4.2.8][REVERT] (skip).")
    pass


def revert_ensure_nologin_not_in_shells():
    """
    [REVERT][5.4.3.1] Bu madde için revert uygulanmaz.
    CIS'e göre /etc/shells içinde 'nologin' bulunmamalıdır.
    """
    logger.info("[CIS 5.4.3.1][REVERT] (skip).")
    pass



def revert_ensure_shell_timeout():
    """
    [REVERT][5.4.3.2] Bu madde için revert uygulanmaz.
    CIS'e göre TMOUT zorunlu olarak yapılandırılmalıdır.
    """
    logger.info("[CIS 5.4.3.2][REVERT] (pass).")
    pass

def revert_umask():
    """
    [REVERT][5.4.3.3] Ensure default user umask is configured
    Uygulanan umask ayarını geri alır (eklenen dosyayı siler).
    """
    try:
        config_file = "/etc/profile.d/50-systemwide_umask.sh"
        if os.path.exists(config_file):
            os.remove(config_file)
            logger.info(f"[CIS 5.4.3.3][REVERT] {config_file} dosyası silindi, umask revert edildi.")
            return True, f"{config_file} silindi, umask revert edildi."
        else:
            logger.info(f"[CIS 5.4.3.3][REVERT] {config_file} zaten yok, yapılacak işlem yok.")
            return True, "Zaten revert durumda."
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.4.3.3][REVERT] Umask revert sırasında hata: {msg}")
        return False, msg