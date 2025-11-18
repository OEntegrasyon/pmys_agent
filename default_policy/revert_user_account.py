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
    CIS 5.4.1.1 - Revert (Debian default)
    Debian'ın varsayılan PASS_MAX_DAYS değeri 99999'dur.
    Bu fonksiyon, /etc/login.defs içindeki PASS_MAX_DAYS satırını 99999 olarak geri ayarlar.
    """
    login_defs = "/etc/login.defs"
    if not os.path.exists(login_defs):
        logger.warning(f"[CIS 5.4.1.1][REVERT] {login_defs} bulunamadı.")
        return False, f"{login_defs} bulunamadı."

    try:
        with open(login_defs, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if re.match(r'^\s*PASS_MAX_DAYS\b', line, re.IGNORECASE):
                new_lines.append("PASS_MAX_DAYS   99999\n")
                found = True
            else:
                new_lines.append(line)

        # Eğer hiç yoksa en alta ekler
        if not found:
            new_lines.append("\nPASS_MAX_DAYS   99999\n")

        temp_path = login_defs + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        os.replace(temp_path, login_defs)

        logger.info("[CIS 5.4.1.1][REVERT] PASS_MAX_DAYS 99999 olarak Debian varsayılanına döndürüldü.")

        # Kullanıcı bazlı chage değerlerini de Debian default’a çeker
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 2:
                    user = parts[0]
                    uid = int(parts[2])
                    if uid >= 1000 and "nologin" not in line and "false" not in line:
                        run_command(["chage", "--maxdays", "99999", user])
        run_command(["chage", "--maxdays", "99999", "root"])

        return True, "PASS_MAX_DAYS varsayılanı (99999) olarak geri ayarlandı."

    except Exception as e:
        msg = f"Hata: {e}"
        logger.error(f"[CIS 5.4.1.1][REVERT] {msg}")
        return False, msg



def revert_min_password_days(username=None, param=None):
    """
    Debian default revert:
    PASS_MIN_DAYS değerini Debian varsayılanı olan 0'a döndürür.
    Kullanıcıların min_days değerlerini de chage ile 0 yapar.
    """
    try:
        revert_value = int(param.get("value", 0)) if param else 0

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
        logger.info(f"[CIS 5.4.1.2][REVERT] /etc/login.defs PASS_MIN_DAYS {revert_value} (Debian default) olarak güncellendi")

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
                            logger.warning(f"[CIS 5.4.1.2][REVERT] {user} revert hatası: {out}")
                        else:
                            logger.info(f"[CIS 5.4.1.2][REVERT] {user} için mindays={revert_value} (Debian default) olarak ayarlandı")

        return True, f"PASS_MIN_DAYS Debian varsayılanına (0) döndürüldü"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.4.1.2][REVERT] Hata: {msg}")
        return False, msg



def revert_password_warn_days(username=None, param=None):
    """
    CIS 5.4.1.3 - Password Warning Days
    Revert (Debian default): PASS_WARN_AGE değerini 7'ye döndürür.
    Tüm kullanıcıların uyarı gün sayılarını da 7 yapar.
    """
    try:
        revert_value = int(param.get("revert_value", 7)) if param else 7

        # login.defs revert
        with open("/etc/login.defs", "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if re.search(r"^\s*PASS_WARN_AGE\s+", line) and not line.strip().startswith("#"):
                new_lines.append(f"PASS_WARN_AGE   {revert_value}\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(f"\nPASS_WARN_AGE   {revert_value}\n")

        with open("/etc/login.defs", "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # shadow revert
        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    user = parts[0]
                    passwd_field = parts[1]
                    if passwd_field.startswith("$"):
                        success, out = run_command(["chage", "--warndays", str(revert_value), user])
                        if success:
                            logger.info(f"[CIS 5.4.1.3][REVERT] {user} PASS_WARN_AGE={revert_value}")
                        else:
                            logger.warning(f"[CIS 5.4.1.3][REVERT] {user} revert hatası: {out}")

        logger.info(f"[CIS 5.4.1.3][REVERT] PASS_WARN_AGE Debian default (7 gün) olarak ayarlandı.")
        return True, f"PASS_WARN_AGE Debian default'a (7) döndürüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.4.1.3][REVERT] Hata: {msg}")
        return False, msg


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
    Debian varsayılanı: -1 (hiç devre dışı bırakma)
    """
    try:
        revert_days = str((param or {}).get("revert_days", -1))

        run_command(["useradd", "-D", "-f", revert_days])

        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 8:
                    continue
                user, passwd = parts[0], parts[1]
                if not passwd.startswith("$"):  # sadece şifreli hesaplar için
                    continue
                run_command(["chage", "--inactive", revert_days, user])

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



def revert_ensure_shell_timeout(username=None, param=None):
    """
    [REVERT][5.4.3.2] Revert default user shell timeout (TMOUT) configuration.
    
    CIS 5.4.3.2 Apply metodu ile /etc/profile.d/timeout.sh dosyasına eklenen
    TMOUT, readonly TMOUT ve export TMOUT satırlarını geri alır.
    """
    try:
        timeout_file = "/etc/profile.d/timeout.sh"
        mode = (param or {}).get("mode", "remove")

        if not os.path.exists(timeout_file):
            logger.info("[REVERT][5.4.3.2] timeout.sh dosyası bulunamadı, işlem gerekmedi.")
            return True, "timeout.sh zaten yoktu, işlem gerekmedi."

        if mode == "remove":
            os.remove(timeout_file)
            logger.info(f"[REVERT][5.4.3.2] {timeout_file} dosyası silindi (TMOUT devre dışı bırakıldı).")
            return True, f"{timeout_file} dosyası silindi ve TMOUT revert edildi."

        elif mode == "comment":
            new_lines = []
            with open(timeout_file, "r", encoding="utf-8") as f:
                for line in f:
                    if any(kw in line for kw in ["TMOUT", "readonly TMOUT", "export TMOUT"]):
                        if not line.strip().startswith("#"):
                            new_lines.append("# " + line)
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)

            with open(timeout_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            logger.info(f"[REVERT][5.4.3.2] {timeout_file} içindeki TMOUT satırları yorum satırına alındı.")
            return True, f"{timeout_file} içindeki TMOUT satırları yorum satırına alındı."

        else:
            logger.error(f"[REVERT][5.4.3.2] Geçersiz mode parametresi: {mode}")
            return False, f"Geçersiz mode parametresi: {mode}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[REVERT][5.4.3.2] Hata oluştu: {msg}")
        return False, msg


def revert_umask():
    """
    [REVERT][5.4.3.3] Ensure default user umask is configured
    Debian default (hiç umask tanımı olmayan) hale döner.
    """
    try:
        config_file = "/etc/profile.d/50-systemwide_umask.sh"

        if os.path.exists(config_file):
            os.remove(config_file)
            logger.info(f"[CIS 5.4.3.3][REVERT] {config_file} silindi.")

        for path in ["/etc/profile", "/etc/login.defs"]:
            if not os.path.exists(path):
                continue
            run_command(["bash", "-c", f"sed -i '/^umask [0-9][0-9][0-9]/d' {path}"])
            logger.info(f"[CIS 5.4.3.3][REVERT] {path} içindeki aktif umask satırları kaldırıldı.")

        logger.info("[CIS 5.4.3.3][REVERT] Sistem Debian default (yorumlu) duruma döndürüldü.")
        return True, "Umask Debian varsayılanına (yorumlu) döndürüldü."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.4.3.3][REVERT] Hata: {msg}")
        return False, msg
