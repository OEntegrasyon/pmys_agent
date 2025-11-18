###############################################################################################################################
###                                                                                                                         ###
###                                             CIS 5.4 User Accounts and Environment                                       ###
###                                                                                                                         ###
###############################################################################################################################

import os
import glob
import pwd
import grp
import stat
import shutil
import re

from datetime import datetime

from utils import run_command
from logger import logger


def check_password_expiration(max_days):
    """
    CIS 5.4.1.1 - Ensure password expiration is configured
    PASS_MAX_DAYS değerini /etc/login.defs ve /etc/shadow dosyalarında kontrol eder.
    """
    try:
        # /etc/login.defs kontrolü
        with open("/etc/login.defs", "r") as f:
            content = f.readlines()

        current_value = None
        for line in content:
            match = re.match(r'^\s*PASS_MAX_DAYS\s+(\d+)', line)
            if match:
                current_value = int(match.group(1))
                break

        if current_value is None:
            logger.warning("[CIS 5.4.1.1] PASS_MAX_DAYS ayarı bulunamadı.")
            return False, None

        if current_value > max_days or current_value < 1:
            logger.warning(f"[CIS 5.4.1.1] PASS_MAX_DAYS uygunsuz: {current_value}")
            return False, current_value

        # /etc/shadow kontrolü
        bad_users = []
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 5:
                    user, passwd, _, _, max_days_field = parts[:5]
                    if re.match(r'^\$.+', passwd):  # şifreli kullanıcı
                        try:
                            val = int(max_days_field)
                            if val > max_days or val < 1:
                                bad_users.append(f"{user}:{val}")
                        except ValueError:
                            logger.warning(f"[CIS 5.4.1.1] {user} için geçersiz PASS_MAX_DAYS değeri: {max_days_field}")

        if bad_users:
            logger.warning(f"[CIS 5.4.1.1] Uygunsuz kullanıcılar: {', '.join(bad_users)}")
            return False, current_value

        logger.info(f"[CIS 5.4.1.1] PASS_MAX_DAYS doğru: {current_value}")
        return True, current_value

    except Exception as e:
        logger.error(f"[CIS 5.4.1.1] Kontrol sırasında hata: {e}")
        return False, None


def apply_password_expiration(username=None, param=None):
    """
    CIS 5.4.1.1 - Ensure password expiration is configured
    Tüm kullanıcılar için PASS_MAX_DAYS değerini uygular.
    """
    try:
        max_days = int(param.get("max_days", 365))
        login_defs = "/etc/login.defs"

        if not os.path.exists(login_defs):
            return False, f"{login_defs} bulunamadı."

        with open(login_defs, "r") as f:
            lines = f.readlines()

        updated = False
        new_lines = []
        for line in lines:
            if line.strip().startswith("PASS_MAX_DAYS"):
                new_lines.append(f"PASS_MAX_DAYS   {max_days}\n")
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            new_lines.append(f"PASS_MAX_DAYS   {max_days}\n")

        backup_file = f"{login_defs}.bak"
        if not os.path.exists(backup_file):
            os.rename(login_defs, backup_file)
            logger.info(f"[apply_password_expiration] Yedek oluşturuldu: {backup_file}")
        else:
            os.remove(backup_file)
            os.rename(login_defs, backup_file)
            logger.info(f"[apply_password_expiration] Mevcut yedek yenilendi: {backup_file}")

        with open(login_defs, "w") as f:
            f.writelines(new_lines)

        logger.info(f"[apply_password_expiration] {login_defs} PASS_MAX_DAYS {max_days} olarak güncellendi.")

        # root kullanıcısı için maxdays + last change date ayarla
        run_command(["chage", "--maxdays", str(max_days), "root"])
        run_command(["chage", "-d", datetime.now().strftime("%Y-%m-%d"), "root"])

        # Normal kullanıcılar için uygula
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 2:
                    user = parts[0]
                    uid = int(parts[2])
                    if uid >= 1000 and "nologin" not in line and "false" not in line:
                        run_command(["chage", "--maxdays", str(max_days), user])

        return True, f"Tüm kullanıcılar için PASS_MAX_DAYS {max_days} olarak ayarlandı."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_password_expiration] {msg}")
        return False, msg




def check_min_password_days(expected_value=1):
    """
    CIS 5.4.1.2 - Ensure minimum password days is configured

    Returns: (bool, message)    
    """
    try:
        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            logger.warning("[check_min_password_days] /etc/login.defs bulunamadı.")
            return False, "/etc/login.defs bulunamadı"

        # /etc/login.defs içinden PASS_MIN_DAYS'i bul
        current_value = None
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                # ignore yorum satırları
                line_strip = line.strip()
                if not line_strip or line_strip.startswith("#"):
                    continue
                m = re.match(r'^\s*PASS_MIN_DAYS\s+(\d+)\b', line)
                if m:
                    current_value = int(m.group(1))
                    break

        if current_value is None:
            logger.warning("[check_min_password_days] /etc/login.defs içinde PASS_MIN_DAYS bulunamadı.")
            return False, "/etc/login.defs içinde PASS_MIN_DAYS bulunamadı"

        if current_value < expected_value:
            logger.warning(f"[check_min_password_days] /etc/login.defs PASS_MIN_DAYS={current_value}, beklenen >= {expected_value}")
            return False, f"/etc/login.defs PASS_MIN_DAYS={current_value}, beklenen >= {expected_value}"

        # /etc/shadow kontrolü (şifreli hesaplar)
        shadow = "/etc/shadow"
        if not os.path.exists(shadow):
            logger.warning("[check_min_password_days] /etc/shadow bulunamadı.")
            return False, "/etc/shadow bulunamadı"

        bad_users = []
        with open(shadow, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if len(parts) < 5:
                    continue
                username = parts[0]
                passwd_field = parts[1]
                # passwd_field başlangıcı '$' ise parola hash'lenmiş demek (yerel hesap)
                if passwd_field and passwd_field.startswith("$"):
                    # parts[3] = min days
                    try:
                        min_days = int(parts[3]) if parts[3] != "" else 0
                    except ValueError:
                        min_days = 0
                    if min_days < expected_value:
                        bad_users.append(f"{username}:{min_days}")

        if bad_users:
            logger.warning(f"[check_min_password_days] Uygunsuz kullanıcılar: {', '.join(bad_users)}")
            return False, f"/etc/shadow içinde hatalı kullanıcılar var: {', '.join(bad_users)}"

        logger.info(f"[check_min_password_days] PASS_MIN_DAYS uygun (login.defs={current_value}, users OK).")
        return True, f"PASS_MIN_DAYS ayarı uygun (>= {expected_value})"

    except Exception as e:
        logger.error(f"[check_min_password_days] Hata: {e}")
        return False, str(e)


def apply_min_password_days(username=None, param=None):
    """
    CIS 5.4.1.2 - Ensure minimum password days is configured

    Param: param should be a dict like {"value": 1}
    Returns (bool, message)
    """
    try:
        expected_value = int(param.get("value", 1)) if param else 1

        ok, msg = check_min_password_days(expected_value)
        if ok:
            return True, f"PASS_MIN_DAYS zaten uygun: {msg}"

        logger.info(f"[apply_min_password_days] Uygun değil: {msg} -> Düzeltiliyor...")

        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            return False, "/etc/login.defs bulunamadı"

        bak = f"{login_defs}.bak"
        shutil.copy(login_defs, bak)   
        logger.info(f"[apply_min_password_days] Yedek alındı: {bak}")

        found = False
        new_lines = []
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                if re.match(r'^\s*#', line) or line.strip() == "":
                    new_lines.append(line)
                    continue
                m = re.match(r'^\s*PASS_MIN_DAYS\s+(\d+)\b', line)
                if m:
                    new_lines.append(f"PASS_MIN_DAYS   {expected_value}\n")
                    found = True
                else:
                    new_lines.append(line)

        if not found:
            # sondan önce boş satır ekler şekilde append
            new_lines.append(f"\nPASS_MIN_DAYS   {expected_value}\n")

        tmp_path = f"{login_defs}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        os.replace(tmp_path, login_defs)
        logger.info(f"[apply_min_password_days] /etc/login.defs güncellendi: PASS_MIN_DAYS {expected_value}")

        # Kullanıcıları chage ile düzelt (sadece yerel, şifreli hesaplar)
        shadow = "/etc/shadow"
        with open(shadow, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if len(parts) < 5:
                    continue
                user = parts[0]
                passwd_field = parts[1]
                if passwd_field and passwd_field.startswith("$"):
                    try:
                        min_days = int(parts[3]) if parts[3] != "" else 0
                    except ValueError:
                        min_days = 0
                    if min_days < expected_value:
                        # chage ile güncelle
                        rc, out = run_command(["chage", "--mindays", str(expected_value), user])
                        if not rc:
                            logger.warning(f"[apply_min_password_days] chage hatası {user}: {out}")
                        else:
                            logger.info(f"[apply_min_password_days] {user} için mindays={expected_value} ayarlandı")

        ok2, msg2 = check_min_password_days(expected_value)
        if ok2:
            return True, f"PASS_MIN_DAYS başarıyla uygulandı ({expected_value})"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[apply_min_password_days] Hata: {msg}")
        return False, msg




def check_password_warn_days(expected_value=7):
    """
    CIS 5.4.1.3 - Ensure password expiration warning days is configured
    """
    try:
        # /etc/login.defs kontrolü
        defs_value = None
        with open("/etc/login.defs", "r", encoding="utf-8") as f:
            for line in f:
                if re.search(r"^\s*PASS_WARN_AGE\s+", line) and not line.strip().startswith("#"):
                    try:
                        defs_value = int(line.split()[1])
                    except (ValueError, IndexError):
                        defs_value = 0
                    break

        if defs_value is None:
            return False, "PASS_WARN_AGE bulunamadı"
        if defs_value < expected_value:
            return False, f"/etc/login.defs PASS_WARN_AGE={defs_value}, beklenen en az {expected_value}"

        # /etc/shadow kontrolü (WARN alanı = index 5)
        bad_users = []
        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6 and parts[1].startswith("$"):
                    try:
                        warn_days = int(parts[5]) if parts[5] else 0
                    except (ValueError, IndexError):
                        warn_days = 0
                    if warn_days < expected_value:
                        bad_users.append(f"{parts[0]}:{warn_days}")

        if bad_users:
            return False, f"/etc/shadow içinde farklı kullanıcılar var: {', '.join(bad_users)}"

        return True, f"PASS_WARN_AGE tüm sistemde {expected_value} olarak ayarlı"
    except Exception as e:
        return False, str(e)


def apply_password_warn_days(username=None, param=None):
    """
    CIS 5.4.1.3 - PASS_WARN_AGE uygula
    Tüm kullanıcılar ve /etc/login.defs dosyası için gelen değeri sabitler.
    """
    try:
        expected_value = int(param.get("value", 7)) if param else 7
        ok, msg = check_password_warn_days(expected_value)
        if ok:
            return True, f"PASS_WARN_AGE zaten uygun: {msg}"

        logger.info(f"[APPLY][password_warn_days] Uyumsuzluk tespit edildi: {msg} → Düzeltiliyor...")

        login_defs = "/etc/login.defs"
        new_lines = []
        updated = False
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                if re.match(r"^\s*PASS_WARN_AGE\s+", line) and not line.strip().startswith("#"):
                    new_lines.append(f"PASS_WARN_AGE   {expected_value}\n")
                    updated = True
                else:
                    new_lines.append(line)
        if not updated:
            new_lines.append(f"\nPASS_WARN_AGE   {expected_value}\n")

        shutil.copy(login_defs, f"{login_defs}.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        with open(login_defs, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        logger.info(f"[APPLY][password_warn_days] {login_defs} güncellendi (PASS_WARN_AGE={expected_value})")

        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6 and parts[1].startswith("$"):
                    user = parts[0]
                    success, output = run_command(["chage", "--warndays", str(expected_value), user])
                    if success:
                        logger.info(f"[APPLY][password_warn_days] {user} için PASS_WARN_AGE {expected_value} olarak ayarlandı.")
                    else:
                        logger.error(f"[APPLY][password_warn_days] {user} için chage hatası: {output}")

        ok2, msg2 = check_password_warn_days(expected_value)
        if ok2:
            logger.info(f"[APPLY][password_warn_days] PASS_WARN_AGE başarıyla {expected_value} olarak sabitlendi.")
            return True, f"Düzeltme uygulandı: {expected_value}"
        else:
            logger.error(f"[APPLY][password_warn_days] Düzeltme başarısız: {msg2}")
            return False, f"Düzeltme başarısız: {msg2}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][password_warn_days] Hata: {msg}")
        return False, msg




def check_password_hashing_algorithm(expected_algorithms=("SHA512", "YESCRYPT")):
    """
    CIS 5.4.1.4 - Ensure strong password hashing algorithm is configured
    /etc/login.defs içindeki ENCRYPT_METHOD ayarını kontrol eder.
    """
    try:
        cmd = ["grep", "-Pi", r"^\s*ENCRYPT_METHOD\s+\w+", "/etc/login.defs"]
        success, out = run_command(cmd)
        if not success or not out.strip():
            return False, "/etc/login.defs içinde ENCRYPT_METHOD bulunamadı"

        # Yorum satırlarını filtreler
        lines = [l for l in out.splitlines() if not l.strip().startswith("#")]
        if not lines:
            return False, "Yalnızca yorum satırları bulundu, etkin satır yok"

        parts = lines[0].strip().split()
        if len(parts) < 2:
            return False, f"ENCRYPT_METHOD satırı geçersiz: {lines[0]}"

        current_alg = parts[1].upper()
        if current_alg not in expected_algorithms:
            return False, f"ENCRYPT_METHOD {current_alg}, beklenen {expected_algorithms}"

        return True, f"ENCRYPT_METHOD doğru: {current_alg}"

    except Exception as e:
        logger.error(f"[CIS 5.4.1.4][CHECK] Hata: {e}")
        return False, str(e)



def apply_password_hashing_algorithm(username=None, param=None):
    """
    CIS 5.4.1.4 - Ensure strong password hashing algorithm is configured
    ENCRYPT_METHOD değerini SHA512 veya YESCRYPT olarak ayarlar.
    """
    try:
        param = param or {}
        expected_algorithm = param.get("expected_algorithm", "SHA512").upper()

        ok, msg = check_password_hashing_algorithm((expected_algorithm,))
        if ok:
            return True, f"ENCRYPT_METHOD zaten uygun: {msg}"

        logger.info(f"[APPLY][password_hashing_algorithm] Uyumsuz: {msg} → Düzeltiliyor...")

        login_defs = "/etc/login.defs"
        backup_file = f"{login_defs}.bak"

        try:
            shutil.copy(login_defs, backup_file)
            logger.info(f"[APPLY][password_hashing_algorithm] Yedek oluşturuldu: {backup_file}")
        except Exception as e:
            logger.warning(f"[APPLY][password_hashing_algorithm] Yedekleme hatası: {e}")

        # Dosyayı okur, yorumları koruyarak günceller
        new_lines = []
        updated = False
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                if re.match(r"^\s*ENCRYPT_METHOD\s+\w+", line) and not line.strip().startswith("#"):
                    new_lines.append(f"ENCRYPT_METHOD {expected_algorithm}\n")
                    updated = True
                else:
                    new_lines.append(line)

        if not updated:
            new_lines.append(f"\nENCRYPT_METHOD {expected_algorithm}\n")

        tmp_path = f"{login_defs}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        os.replace(tmp_path, login_defs)

        logger.info(f"[APPLY][password_hashing_algorithm] /etc/login.defs güncellendi → ENCRYPT_METHOD {expected_algorithm}")

        ok2, msg2 = check_password_hashing_algorithm((expected_algorithm,))
        if ok2:
            logger.info(f"[APPLY][password_hashing_algorithm] ENCRYPT_METHOD başarıyla {expected_algorithm} olarak ayarlandı.")
            return True, f"ENCRYPT_METHOD başarıyla {expected_algorithm} olarak ayarlandı."
        else:
            logger.error(f"[APPLY][password_hashing_algorithm] Doğrulama başarısız: {msg2}")
            return False, f"Ayar sonrası doğrulama başarısız: {msg2}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][password_hashing_algorithm] Hata: {msg}")
        return False, msg



def check_inactive_password_lock(expected_days=45):
    """
    CIS 5.4.1.5 - Ensure inactive password lock is configured
    """
    try:
        # Varsayılan değeri kontrol eder
        success, out = run_command(["useradd", "-D"])
        if success:
            m = re.search(r"INACTIVE=(\S+)", out)
            if m:
                current_default = m.group(1)
                if current_default in ("-1", "", None) or int(current_default) > expected_days:
                    return False, f"useradd varsayılan INACTIVE={current_default}, beklenen <= {expected_days}"
            else:
                return False, "useradd çıktısında INACTIVE bulunamadı"

        # /etc/shadow kontrolü
        non_compliant = []
        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user, passwd, inactive = parts[0], parts[1], parts[6]
                if not passwd.startswith("$"):
                    continue

                if inactive in ("", None, "-1"):
                    non_compliant.append(f"{user}:{inactive or 'empty'}")
                else:
                    try:
                        inactive_val = int(inactive)
                        if inactive_val > expected_days:
                            non_compliant.append(f"{user}:{inactive}")
                    except ValueError:
                        non_compliant.append(f"{user}:{inactive}")

        if non_compliant:
            return False, f"Uygunsuz kullanıcılar: {', '.join(non_compliant)}"

        return True, f"Tüm kullanıcılar INACTIVE değeri <= {expected_days} uyumlu."
    except Exception as e:
        return False, f"/etc/shadow kontrolünde hata: {e}"


def apply_inactive_password_lock(username=None, param=None):
    """
    CIS 5.4.1.5 - Ensure inactive password lock is configured
    """
    param = param or {}
    days = int(param.get("max_inactive_days", 45))

    ok, msg = check_inactive_password_lock(days)
    if ok:
        return True, f"Zaten uyumlu: {msg}"

    logger.info(f"[APPLY][inactive_password_lock] Uyumsuzluk tespit edildi: {msg} → Düzeltiliyor...")

    success, output = run_command(["useradd", "-D", "-f", str(days)])
    if not success:
        return False, f"useradd varsayılan ayar yapılamadı: {output}"
    logger.info(f"[APPLY][inactive_password_lock] Varsayılan INACTIVE={days} olarak ayarlandı")

    with open("/etc/shadow", "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) < 7:
            new_lines.append(line)
            continue

        user, passwd, inactive = parts[0], parts[1], parts[6]
        if not passwd.startswith("$"):
            new_lines.append(line)
            continue

        fix_needed = False
        if inactive in ("", None, "-1"):
            fix_needed = True
        else:
            try:
                if int(inactive) > days:
                    fix_needed = True
            except ValueError:
                fix_needed = True

        if fix_needed:
            success, out = run_command(["chage", "--inactive", str(days), user])
            if not success:
                logger.warning(f"[APPLY][inactive_password_lock] chage başarısız ({user}), dosya doğrudan güncellenecek: {out}")

            parts[6] = str(days)
            new_lines.append(":".join(parts) + "\n")
            logger.info(f"[APPLY][inactive_password_lock] {user} için INACTIVE {days} olarak zorla yazıldı.")
        else:
            new_lines.append(line)

    backup = f"/etc/shadow.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    shutil.copy("/etc/shadow", backup)
    with open("/etc/shadow", "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    logger.info(f"[APPLY][inactive_password_lock] /etc/shadow güncellendi ve yedek alındı: {backup}")

    ok, msg = check_inactive_password_lock(days)
    if ok:
        return True, f"Tüm kullanıcılar için INACTIVE {days} olarak başarıyla uygulandı."
    else:
        return False, f"Ayar sonrası doğrulama başarısız: {msg}"




def check_last_password_change_in_past():
    """
    CIS 5.4.1.6 - Ensure all users last password change date is in the past.

    Kontrol:
    - /etc/shadow dosyasında hash’li parolası olan kullanıcılar alınır.
    - chage --list ile "Last password change" değeri okunur.
    - Gelecekteki tarih bulunursa uygunsuz sayılır.
    """
    try:
        with open("/etc/shadow", "r") as f:
            lines = f.readlines()

        future_users = []
        now_ts = int(datetime.now().timestamp())

        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue

            username, passwd = parts[0], parts[1]
            if not passwd.startswith("$"):
                continue

            cmd = ["chage", "--list", username]
            code, out = run_command(cmd)
            if code != 0 or not out:
                continue

            for l in out.splitlines():
                if l.startswith("Last password change"):
                    value = l.split(":", 1)[1].strip()
                    if value.lower() == "never":
                        continue

                    try:
                        ts = int(datetime.strptime(value, "%b %d, %Y").timestamp())
                        if ts > now_ts:
                            future_users.append(f"{username}:{value}")
                    except Exception:
                        continue

        if future_users:
            return False, f"Uygunsuz kullanıcılar (gelecekte parola değişimi): {', '.join(future_users)}"

        return True, "Tüm kullanıcıların son parola değiştirme tarihi geçmişte."
    except Exception as e:
        logger.error(f"check_last_password_change_in_past hata: {e}")
        return False, str(e)



def apply_last_password_change_in_past(username=None, param=None):
    """
    CIS 5.4.1.6 remediation:
    - Gelecekte parola değiştirme tarihi olan kullanıcıları düzelt.
    - `chage -d 0 <user>` komutu çalıştırılır (parola expire edilir).
    """
    try:
        status, message = check_last_password_change_in_past()
        if status:
            return True, f"Zaten uygun: {message}"

        logger.warning(f"Parola tarihi uygunsuz: {message} -> Düzeltiliyor...")

        if "Uygunsuz kullanıcılar" in message:
            users = [u.split(":")[0] for u in message.split(": ", 1)[1].split(", ")]
            for user in users:
                run_command(["chage", "-d", "0", user])

        status, message = check_last_password_change_in_past()
        if status:
            return True, "Parola değiştirme tarihleri başarıyla düzeltildi."
        else:
            return False, f"Ayar sonrası doğrulama başarısız: {message}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"apply_last_password_change_in_past hata: {msg}")
        return False, msg




def find_next_free_uid(start_uid=1001, max_uid=60000):
    """
    Sistemde kullanılmayan bir UID bulur.
    start_uid'den başlayarak ilk boş UID'yi döndürür.
    """
    used_uids = {u.pw_uid for u in pwd.getpwall()}
    for uid in range(start_uid, max_uid):
        if uid not in used_uids:
            return uid
    raise ValueError("Boş UID bulunamadı!")



def find_next_free_uid(start_uid=1001, max_uid=60000):
    used_uids = {u.pw_uid for u in pwd.getpwall()}
    for uid in range(start_uid, max_uid):
        if uid not in used_uids:
            return uid
    raise ValueError("Boş UID bulunamadı!")


def check_only_root_uid0():
    try:
        cmd = ["awk", "-F:", "($3 == 0) { print $1 }", "/etc/passwd"]
        code, out = run_command(cmd)

        if not code:
            return False, f"/etc/passwd okunamadı: {out}"

        users = [u.strip() for u in out.splitlines() if u.strip()]
        if users == ["root"]:
            return True, "UID 0 sadece root kullanıcısında var."
        else:
            return False, f"Uygunsuz UID 0 kullanıcıları: {', '.join(users)}"
    except Exception as e:
        logger.error(f"check_only_root_uid0 hata: {e}")
        return False, str(e)


def sync_sudoers(user):
    """
    Kullanıcı UID değiştirilince sudo yetkilerini korumak için
    sudoers dosyalarını kontrol eder. Eğer kullanıcı oradaysa
    isim bazlı olduğundan ek işlem gerekmez ama log yazılır.
    """
    sudoers_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
    found = False
    for sfile in sudoers_files:
        try:
            with open(sfile, "r") as f:
                for line in f:
                    if line.strip().startswith("#"):
                        continue
                    if user in line:
                        found = True
                        logger.info(f"{user} sudoers içinde bulundu ({sfile}) -> isim bazlı olduğundan UID değişiminden etkilenmedi.")
        except Exception as e:
            logger.warning(f"{sfile} okunamadı: {e}")
    if not found:
        logger.debug(f"{user} sudoers içinde bulunmadı.")


def apply_only_root_uid0(username=None, param=None):
    """ CIS 5.4.2.1 Ensure root is the only UID 0 account """
    try:
        param = param or {}
        start_uid = int(param.get("start_uid", 1001))

        status, message = check_only_root_uid0()
        if status:
            return True, f"Zaten uygun: {message}"

        logger.warning(f"UID 0 uygunsuz: {message} -> Düzeltiliyor...")

        if "Uygunsuz UID 0 kullanıcıları" in message:
            users = message.split(": ", 1)[1].split(", ")
            for user in users:
                if user == "root":
                    continue

                new_uid = find_next_free_uid(start_uid)

                run_command(["usermod", "-u", str(new_uid), user])
                logger.info(f"{user} UID 0 -> {new_uid} olarak değiştirildi")

                try:
                    grp.getgrnam(user)
                    run_command(["groupmod", "-g", str(new_uid), user])
                    logger.info(f"{user} grubunun GID’si {new_uid} yapıldı")
                except KeyError:
                    logger.debug(f"{user} grubuna gerek yok (bulunamadı)")

                sync_sudoers(user)

                start_uid = new_uid + 1  

        status, message = check_only_root_uid0()
        if status:
            return True, "UID 0 sadece root’a ait olacak şekilde düzeltildi."
        else:
            return False, f"Ayar sonrası doğrulama başarısız: {message}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"apply_only_root_uid0 hata: {msg}")
        return False, msg



def check_only_root_gid0():
    """

    Kontrol:
    - UID root olan kullanıcı GID=0 olmalı
    - root dışındaki kullanıcıların GID=0 olmaması gerekir
    """
    try:
        success, message = run_command([
            "awk",
            "-F:",
            '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}',
            "/etc/passwd"
        ])

        if not success:
            return False, f"Kontrol sırasında hata: {message}"

        lines = message.strip().splitlines()
        if lines == ["root:0"]:
            return True, "Sadece root kullanıcısı GID 0 kullanıyor."
        else:
            return False, f"GID 0 kullanan uygunsuz hesaplar bulundu: {', '.join(lines)}"
    except Exception as e:
        logger.error(f"check_only_root_gid0 hata: {e}")
        return False, str(e)


def apply_only_root_gid0(username=None, param=None):
    """
    5.4.2.2 Ensure root is the only GID 0 account (CIS)

    Root kullanıcısının GID'sini 0 yapar,
    Root grubunu 0 yapar,
    Root dışındaki kullanıcıları GID 0'dan çıkarır.
    """
    try:
        status, message = check_only_root_gid0()
        if status:
            return True, f"Uygun: {message}"

        logger.info(f"Uygunsuz GID 0 hesapları bulundu -> {message}")

        run_command(["usermod", "-g", "0", "root"])
        logger.info("Root kullanıcısının GID değeri 0 olarak ayarlandı.")

        run_command(["groupmod", "-g", "0", "root"])
        logger.info("Root grubunun GID değeri 0 olarak ayarlandı.")

        success, out = run_command([
            "awk", "-F:", '($1 !~ /^(sync|shutdown|halt|operator|root)/ && $4=="0") {print $1}', "/etc/passwd"
        ])
        users = out.strip().splitlines()

        if users:
            for user in users:

                success, gids_out = run_command(["awk", "-F:", "{print $3}", "/etc/group"])
                used_gids = set(map(int, gids_out.strip().splitlines()))
                new_gid = 1001
                while new_gid in used_gids:
                    new_gid += 1

                run_command(["groupadd", "-g", str(new_gid), f"{user}_grp"])
                # Kullanıcının GID'sini değiştir
                run_command(["usermod", "-g", str(new_gid), user])
                logger.info(f"Kullanıcı {user} için yeni GID oluşturuldu: {new_gid}")

        status, message = check_only_root_gid0()
        if status:
            return True, "Tüm uygunsuz GID 0 kullanıcıları düzeltildi."
        else:
            return False, f"Düzeltme sonrası hâlâ uygunsuz kullanıcılar var: {message}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"apply_only_root_gid0 hata: {msg}")
        return False, msg




def check_only_root_gid0():
    """
    5.4.2.3 Ensure group root is the only GID 0 group (Check)
    Açıklama:
        root grubu dışında GID=0 olan başka grup bulunmamalıdır.
    """
    try:
        cmd = ["awk", "-F:", '$3=="0"{print $1":"$3}', "/etc/group"]
        success, output = run_command(cmd)

        if not success:
            logger.error(f"[CHECK][5.4.2.3] Komut çalıştırılamadı: {output}")
            return False, output

        lines = output.strip().split("\n") if output.strip() else []
        if lines == ["root:0"]:
            logger.info("[CHECK][5.4.2.3] Sadece root grubunun GID=0 olduğu doğrulandı.")
            return True, "Sadece root grubunun GID=0 olduğu doğrulandı."
        else:
            logger.warning(f"[CHECK][5.4.2.3] GID=0 grubuna sahip başka gruplar bulundu: {lines}")
            return False, f"GID=0 grubuna sahip başka gruplar bulundu: {lines}"

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.3] Hata: {e}")
        return False, str(e)


def apply_only_root_group_gid0(username=None, param=None):
    """
    5.4.2.3 Ensure group root is the only GID 0 group (Apply)
    Açıklama:
        root grubunun GID’si 0 olacak şekilde düzeltilir.
        Root dışındaki GID=0 grupları sadece loglanır, otomatik değiştirilmez.
    """
    try:
        check_ok, check_msg = check_only_root_gid0()
        if check_ok:
            logger.info("[APPLY][5.4.2.3] Uyum zaten sağlanıyor, işlem yapılmadı.")
            return True, "Uyum zaten sağlanıyor."


        cmd = ["awk", "-F:", '$3=="0"{print $1}', "/etc/group"]
        success, output = run_command(cmd)
        if not success:
            logger.error(f"[APPLY][5.4.2.3] Grup listesi alınamadı: {output}")
            return False, output

        groups = output.strip().split("\n") if output.strip() else []
        log_groups = [grp for grp in groups if grp != "root"]

        if log_groups:
            logger.warning(f"[APPLY][5.4.2.3] Root dışındaki GID=0 gruplar (manuel inceleme gerekli): {log_groups}")
            return False, f"Root dışındaki GID=0 gruplar: {log_groups}"


        cmd_root = ["groupmod", "-g", "0", "root"]
        run_command(cmd_root)
        logger.info("[APPLY][5.4.2.3] root grubunun GID’si 0 olarak ayarlandı.")

        return True, "Sadece root grubunun GID=0 olduğu doğrulandı ve root güncellendi."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][5.4.2.3] Hata: {msg}")
        return False, msg



def check_root_account_access():
    """
    5.4.2.4 Ensure root account access is controlled (Check)
    Açıklama:
        root kullanıcısının şifresi olmalı (P) veya hesap kilitli (L) olmalıdır.
    """
    try:
        cmd = ["passwd", "-S", "root"]
        success, output = run_command(cmd)
        if not success:
            logger.error(f"[CHECK][5.4.2.4] Komut çalıştırılamadı: {output}")
            return False, output


        if any(status in output for status in [" P ", " L "]):
            logger.info(f"[CHECK][5.4.2.4] Root hesabı güvenli: {output.strip()}")
            return True, output.strip()
        else:
            logger.warning(f"[CHECK][5.4.2.4] Root hesabı kontrol dışı: {output.strip()}")
            return False, output.strip()

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.4] Hata: {e}")
        return False, str(e)


def apply_root_account_access(username=None, param=None):
    """
    5.4.2.4 Ensure root account access is controlled (Apply)
    Açıklama:
        Root hesabı için şifre atanır veya hesap kilitlenir.
    Parametre:
        param (dict): {"action": "lock"|"set_password", "password": "<şifre>"}
    """
    try:
        check_ok, check_msg = check_root_account_access()
        if check_ok:
            logger.info("[APPLY][5.4.2.4] Root hesabı zaten güvenli, işlem yapılmadı.")
            return True, "Root hesabı zaten güvenli."

        action = param.get("action") if param else "lock"

        if action == "lock":
            success, out = run_command(["usermod", "-L", "root"])
            if success:
                logger.info("[APPLY][5.4.2.4] Root hesabı kilitlendi.")
                return True, "Root hesabı kilitlendi."
            else:
                logger.error(f"[APPLY][5.4.2.4] Root hesabı kilitlenemedi: {out}")
                return False, out

        elif action == "set_password":
            password = param.get("password")
            if not password:
                logger.error("[APPLY][5.4.2.4] Yeni şifre belirtilmedi.")
                return False, "Yeni şifre belirtilmedi."


            success, out = run_command(["chpasswd"], input=f"root:{password}")
            if success:
                logger.info("[APPLY][5.4.2.4] Root şifresi başarıyla güncellendi.")
                return True, "Root şifresi güncellendi."
            else:
                logger.error(f"[APPLY][5.4.2.4] Root şifresi güncellenemedi: {out}")
                return False, out

        else:
            logger.error(f"[APPLY][5.4.2.4] Geçersiz action parametresi: {action}")
            return False, f"Geçersiz action parametresi: {action}"

    except Exception as e:
        logger.error(f"[APPLY][5.4.2.4] Hata: {e}")
        return False, str(e)


def _get_root_path_env():
    """sudo -Hiu root env çıktısından PATH değerini al (run_command uyumlu)."""
    success, out = run_command(["sudo", "-Hiu", "root", "env"])
    if not success:
        return False, out, None
    for line in out.splitlines():
        if line.startswith("PATH="):
            return True, None, line.split("=", 1)[1]
    return False, "ROOT PATH env bulunamadı", None


def check_root_path_integrity():
    """
    CIS 5.4.2.5 - Check root PATH integrity.
    Returns: (bool, details)  -> details: list of issues (if False) or success message (if True)
    """
    try:
        ok, err_or_msg, root_path = _get_root_path_env()
        if not ok:
            logger.error(f"[CHECK][5.4.2.5] PATH okunamadı: {err_or_msg}")
            return False, f"PATH okunamadı: {err_or_msg}"

        issues = []
        rp = root_path.strip()
        paths = rp.split(":")

        # Boş (::) kontrolü
        if "::" in rp:
            issues.append("PATH içinde boş dizin (::) bulunuyor")

        # Trailing ':' kontrolü
        if rp.endswith(":"):
            issues.append("PATH ':' ile bitiyor (trailing colon)")

        # Current directory (.) kontrolü
        if any(p == "." for p in paths):
            issues.append("PATH içinde current directory (.) bulunuyor")

        # Her path elemanını kontrol et
        for p in paths:
            if p == "" or p == ".":
                continue

            if not os.path.isabs(p):
                issues.append(f"PATH içinde mutlak olmayan yol: '{p}'")
            # stat ile izin ve sahiplik
            success, stat_out = run_command(["stat", "-Lc", "%a %U %F", p])
            if not success:
                issues.append(f"'{p}' dizin değil veya erişilemiyor ({stat_out})")
                continue

            parts = stat_out.strip().split()
            if len(parts) < 3:
                issues.append(f"Stat çıktısı beklenenden farklı: '{p}' -> {stat_out}")
                continue

            mode_str, owner, ftype = parts[0], parts[1], " ".join(parts[2:])
            try:
                mode = int(mode_str, 8)  # oktal biçiminde
            except Exception:
                issues.append(f"Stat izin parse edilemedi: '{p}' -> {mode_str}")
                continue

            # ftype check: directory olmalı
            ftype_l = ftype.lower()
            if not ("directory" in ftype_l or "dizin" in ftype_l):
                issues.append(f"'{p}' dizin değil (tip: {ftype})")
                continue

            # sahiplik kontrolü
            if owner != "root":
                issues.append(f"Dizin '{p}' root kullanıcısına ait değil (owner={owner})")

            # izin kontrolü: daha izinli (more permissive) olmamalı; 0755'e kıyasla
            # eğer (mode & ~0o755) != 0 => bazı izinler 0755'ten daha gevşek
            if (mode & (~0o755)) != 0:
                issues.append(f"Dizin '{p}' izinleri {oct(mode)}; 0755 veya daha kısıtlı olmalı")

        if issues:
            logger.warning(f"[CHECK][5.4.2.5] Root PATH hataları: {issues}")
            return False, issues

        logger.info("[CHECK][5.4.2.5] Root PATH güvenli")
        return True, "Root PATH güvenli"

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.5] Hata: {e}")
        return False, str(e)


def apply_root_path_integrity(username=None, param=None):
    """
    CIS 5.4.2.5 - Apply remediation where safe.

    param: dict (optional)
      - fix_mode: "repair" veya "remove"  (default "repair")
        * "repair": mümkün olan düzeltmeleri uygular (chown/chmod)
        * "remove": PATH içindeki tehlikeli öğeleri kaldırma önerisi döndürür (otomatik temizleme yapmaz)
    Returns (bool, message_or_list)
    """
    try:
        param = param or {}
        fix_mode = param.get("fix_mode", "repair")

        check_ok, result = check_root_path_integrity()
        if check_ok:
            return True, result

        issues = result if isinstance(result, list) else [result]
        applied = []
        manual = []

        ok, err_or_msg, root_path = _get_root_path_env()
        if not ok:
            return False, f"PATH okunamadı: {err_or_msg}"
        rp = root_path.strip()
        paths = rp.split(":")

        for issue in issues:
            low = issue.lower()
            if "boş dizin" in low or "trailing" in low or "current directory" in low or "mutlak olmayan yol" in low:
                manual.append(issue)
            elif "dizin değil" in low:
                manual.append(issue)
            elif "root kullanıcısına ait değil" in low:
                # issue form: "Dizin '... ' root kullanıcısına ait değil (owner=...)" -> extract between quotes
                try:
                    path = issue.split("'")[1]
                except Exception:
                    path = None
                if path and fix_mode == "repair":
                    s, out = run_command(["chown", "root:root", path])
                    if s:
                        applied.append(f"chown root:root {path}")
                    else:
                        manual.append(f"{issue} (chown başarısız: {out})")
                else:
                    manual.append(issue)
            elif "izinleri" in low:
                try:
                    path = issue.split("'")[1]
                except Exception:
                    path = None
                if path and fix_mode == "repair":
                    s, out = run_command(["chmod", "0755", path])
                    if s:
                        applied.append(f"chmod 0755 {path}")
                    else:
                        manual.append(f"{issue} (chmod başarısız: {out})")
                else:
                    manual.append(issue)
            else:
                manual.append(issue)

        if fix_mode == "remove" and manual:
            advice = [
                "PATH temizliği için kontrol edilecek dosyalar: /etc/profile, /etc/environment, /root/.profile, /root/.bashrc, /etc/bash.bashrc",
                "Bu dosyalarda PATH ayarlarını manuel olarak düzenleyin (tehlikeli girdileri kaldırın)."
            ]
            return False, {"applied": applied, "manual_actions_required": manual, "advice": advice}

        final_ok, final_res = check_root_path_integrity()
        if final_ok:
            return True, {"applied": applied, "manual_actions_required": manual}
        else:
            return False, {"applied": applied, "manual_actions_required": manual, "final_check": final_res}

    except Exception as e:
        logger.error(f"[APPLY][5.4.2.5] Hata: {e}")
        return False, str(e)



def check_root_umask(desired_umask="0027"):
    """
    Root kullanıcısının umask değerini kontrol eder.
    Beklenen değer: desired_umask veya daha kısıtlayıcı.
    
    Returns:
        (bool, str): (Uyumlu mu?, Mesaj)
    """
    try:
        files = ["/root/.bash_profile", "/root/.bashrc"]
        insecure_lines = []

        for file in files:
            if not os.path.exists(file):
                continue

            with open(file, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("umask") and stripped != f"umask {desired_umask}":
                        insecure_lines.append(f"{file}:{line.rstrip()}")

        if not insecure_lines:
            logger.info("[CHECK][5.4.2.6] Root umask güvenli (%s).", desired_umask)
            return True, f"Root umask güvenli ({desired_umask})"
        else:
            logger.warning("[CHECK][5.4.2.6] Root umask güvenli değil. Bulunan satırlar:\n%s",
                           "\n".join(insecure_lines))
            return False, "\n".join(insecure_lines)

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.6] Root umask kontrolünde hata: {e}")
        return False, str(e)


def apply_root_umask(username=None, param=None):
    """
    5.4.2.6 Ensure root user umask is configured
    Root umask değerini uygular.
    Parametre: {"desired_umask": "0027"}
    """
    try:
        param = param or {}
        desired_umask = param.get("desired_umask", "0027")

        compliant, msg = check_root_umask(desired_umask)
        if compliant:
            logger.info("[APPLY][5.4.2.6] Root umask zaten güvenli, işlem yapılmadı.")
            return True, f"Root umask zaten güvenli ({desired_umask})."

        files = ["/root/.bash_profile", "/root/.bashrc"]

        for file in files:
            if not os.path.exists(file):
                continue

            with open(file, "r") as f:
                lines = f.readlines()

            new_lines = []
            umask_set = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("umask"):
                    # Doğru değer zaten varsa ekleme yapmaz
                    if stripped == f"umask {desired_umask}":
                        umask_set = True
                        new_lines.append(line)
                    else:
                        # Diğer umask satırlarını yorum satırına alır
                        if not line.startswith("#"):
                            new_lines.append(f"# {line}")
                        else:
                            new_lines.append(line)
                else:
                    new_lines.append(line)

            # Eğer doğru umask satırı yoksa ekler
            if not umask_set:
                new_lines.append(f"umask {desired_umask}\n")

            with open(file, "w") as f:
                f.writelines(new_lines)

        logger.info(f"[APPLY][5.4.2.6] Root umask {desired_umask} olarak ayarlandı.")
        return True, f"Root umask {desired_umask} olarak ayarlandı."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][5.4.2.6] Root umask uygulanırken hata: {msg}")
        return False, msg




def check_system_accounts_shell():
    """
    [CHECK][5.4.2.7] Ensure system accounts do not have a valid login shell
    root, halt, sync, shutdown, nfsnobody dışındaki sistem hesaplarının
    shell'i /sbin/nologin veya /bin/false olmalı.
    """
    try:
        # UID_MIN değerini al
        success, uid_min_str = run_command(["awk", "/^\\s*UID_MIN/{print $2}", "/etc/login.defs"])
        if not success or not uid_min_str.strip().isdigit():
            logger.error("[CHECK][5.4.2.7] UID_MIN değeri alınamadı.")
            return False, []

        uid_min = int(uid_min_str.strip())

        insecure_users = []
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user, _, uid, _, _, _, shell = parts
                try:
                    uid = int(uid)
                except ValueError:
                    continue

                # root ve bazı özel kullanıcıları atlar
                if user in ("root", "halt", "sync", "shutdown", "nfsnobody"):
                    continue

                # sistem hesabı kontrolü
                if uid < uid_min or uid == 65534:
                    if not (shell.endswith("nologin") or shell.endswith("false")):
                        insecure_users.append(f"{user}:{shell}")

        if not insecure_users:
            logger.info("[CHECK][5.4.2.7] Tüm sistem hesapları güvenli shell kullanıyor.")
            return True, []

        logger.warning("[CHECK][5.4.2.7] Güvenli olmayan shell kullanan hesaplar:\n%s",
                       "\n".join(insecure_users))
        return False, [u.split(":")[0] for u in insecure_users]

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.7] Sistem hesapları shell kontrolünde hata: {e}")
        return False, []


def apply_system_accounts_shell(username=None, param=None):
    """
    [APPLY][5.4.2.7] Sistem hesaplarının shell değerini /sbin/nologin yapar.
    """
    try:
        ok, users = check_system_accounts_shell()
        if ok:
            logger.info("[APPLY][5.4.2.7] Sistem hesapları zaten güvenli.")
            return True, "Sistem hesapları zaten güvenli."

        if not users:
            logger.info("[APPLY][5.4.2.7] Güvensiz shell kullanan sistem hesabı bulunamadı.")
            return False, "Güvensiz shell kullanan sistem hesabı bulunamadı."

        nologin_path = shutil.which("nologin") or "/sbin/nologin"
        applied = []

        for user in users:
            success, msg = run_command(["usermod", "-s", nologin_path, user])
            if success:
                logger.info(f"[APPLY][5.4.2.7] {user} shell {nologin_path} olarak ayarlandı.")
                applied.append(user)
            else:
                logger.error(f"[APPLY][5.4.2.7] {user} shell ayarlanamadı: {msg}")

        return True, f"Aşağıdaki kullanıcıların shell'i {nologin_path} olarak ayarlandı: {', '.join(applied)}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][5.4.2.7] Root umask uygulanırken hata: {msg}")
        return False, msg




def check_accounts_without_login_shell_locked():
    """
    [CHECK][5.4.2.8] Root dışındaki geçerli login shell'i olmayan
    kullanıcıların kilitli olup olmadığını kontrol eder.
    """
    try:
        # Geçerli shell listesi (nologin dışındakiler)
        valid_shells_cmd = [
            "bash", "-c",
            "awk -F/ '$NF != \"nologin\" {print}' /etc/shells "
            "| sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -"
        ]
        success, valid_shells = run_command(valid_shells_cmd)
        if not success or not valid_shells.strip():
            logger.error("[CHECK][5.4.2.8] Geçerli shell listesi alınamadı.")
            return False

        # Login shell olmayan kullanıcıları bulur
        users_cmd = [
            "bash", "-c",
            f"awk -v pat=\"^({valid_shells})$\" -F: "
            "'($1 != \"root\" && $(NF) !~ pat) {print $1}' /etc/passwd"
        ]
        success, users_output = run_command(users_cmd)
        if not success:
            logger.error(f"[CHECK][5.4.2.8] Kullanıcı listesi alınamadı: {users_output}")
            return False

        users = users_output.strip().splitlines() if users_output.strip() else []
        insecure_users = []
        for user in users:
            success, status = run_command(["passwd", "-S", user])
            if success and status and not status.split()[1].startswith("L"):
                insecure_users.append(user)

        if not insecure_users:
            logger.info("[CHECK][5.4.2.8] Geçerli shell'i olmayan tüm hesaplar kilitli durumda.")
            return True
        else:
            logger.warning("[CHECK][5.4.2.8] Kilitli olmayan kullanıcılar bulundu: %s", ", ".join(insecure_users))
            return False

    except Exception as e:
        logger.error(f"[CHECK][5.4.2.8] Hesap kilit kontrolünde hata: {e}")
        return False


def apply_accounts_without_login_shell_locked(username=None, param=None):
    """
    [APPLY][5.4.2.8] Root dışındaki geçerli login shell'i olmayan
    kullanıcıların kilitlenmesini sağlar.
    """
    try:
        if check_accounts_without_login_shell_locked():
            logger.info("[APPLY][5.4.2.8] Hesaplar zaten güvenli durumda, işlem yapılmadı.")
            return True, "Hesaplar zaten güvenli durumda."

        # Geçerli shell listesi
        valid_shells_cmd = [
            "bash", "-c",
            "awk -F/ '$NF != \"nologin\" {print}' /etc/shells "
            "| sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -"
        ]
        success, valid_shells = run_command(valid_shells_cmd)
        if not success or not valid_shells.strip():
            logger.error("[APPLY][5.4.2.8] Geçerli shell listesi alınamadı.")
            return False, "Geçerli shell listesi alınamadı."

        # Login shell olmayan kullanıcıları bul
        users_cmd = [
            "bash", "-c",
            f"awk -v pat=\"^({valid_shells})$\" -F: "
            "'($1 != \"root\" && $(NF) !~ pat) {print $1}' /etc/passwd"
        ]
        success, users_output = run_command(users_cmd)
        if not success:
            logger.error(f"[APPLY][5.4.2.8] Kullanıcı listesi alınamadı: {users_output}")
            return False, f"Kullanıcı listesi alınamadı: {users_output}"

        users = users_output.strip().splitlines() if users_output.strip() else []
        changed = []
        for user in users:
            success, status = run_command(["passwd", "-S", user])
            if success and status and not status.split()[1].startswith("L"):
                run_command(["usermod", "-L", user])
                logger.info(f"[APPLY][5.4.2.8] {user} hesabı kilitlendi.")
                changed.append(user)

        if not changed:
            logger.info("[APPLY][5.4.2.8] İşlem yapılacak kullanıcı bulunamadı.")
        return True, f"Kilitlenen kullanıcılar: {', '.join(changed)}" if changed else "Kilitlenecek kullanıcı bulunamadı."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][5.4.2.8] Hesap kilitleme sırasında hata: {msg}")
        return False, msg



def check_ensure_nologin_not_in_shells():
    """
    5.4.3.1 Ensure nologin is not listed in /etc/shells
    CIS Benchmark Level 2 - Server/Workstation
    """
    try:
        command = ["grep", "-Ps", r'^\h*([^#\n\r]+)?/nologin\b', "/etc/shells"]
        success, output = run_command(command)

        if success and output.strip():
            logger.warning("[CHECK][5.4.3.1] /etc/shells dosyasında 'nologin' bulundu.")
            return False, "/etc/shells dosyasında 'nologin' bulundu."
        else:
            logger.info("[CHECK][5.4.3.1] /etc/shells dosyasında 'nologin' bulunmuyor.")
            return True, "/etc/shells dosyasında 'nologin' bulunmuyor."
    except Exception as e:
        logger.error(f"[CHECK][5.4.3.1] Kontrol sırasında hata oluştu: {e}")
        return False, str(e)


def apply_ensure_nologin_not_in_shells(username=None, param=None):
    """
    5.4.3.1 Ensure nologin is not listed in /etc/shells
    CIS Benchmark Level 2 - Server/Workstation
    """
    try:
        success, message = check_ensure_nologin_not_in_shells()
        if success:
            return True, "Herhangi bir işlem yapılmasına gerek yok."

        command = ["sed", "-i", "/nologin/d", "/etc/shells"]
        success, output = run_command(command)

        if success:
            logger.info("[APPLY][5.4.3.1] /etc/shells dosyasından 'nologin' kaldırıldı.")
            return True, "/etc/shells dosyasından 'nologin' kaldırıldı."
        else:
            logger.error(f"[APPLY][5.4.3.1] Düzenleme başarısız: {output}")
            return False, output
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[APPLY][5.4.3.1] İşlem sırasında hata oluştu: {msg}")
        return False, msg




def check_ensure_shell_timeout():
    """
    CIS 5.4.3.2 - Default user shell timeout (TMOUT) kontrolü.
    Gereksinimler:
      - TMOUT <= 900 olmalı
      - readonly TMOUT olmalı
      - export TMOUT olmalı
      - Hatalı TMOUT (0, 900+, 4+ haneli sayı) olmamalı
    """
    try:
        target_files = ["/etc/bashrc", "/etc/profile"] + \
                       [f"/etc/profile.d/{f}" for f in os.listdir("/etc/profile.d") if f.endswith(".sh")]

        found_valid = False
        found_invalid = False

        re_tmout_valid = re.compile(r'^\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b')
        re_tmout_readonly = re.compile(r'^\s*(readonly\s+TMOUT(\s+|;|$))')
        re_tmout_export = re.compile(r'^\s*(export\s+TMOUT(\s+|;|$))')

        re_tmout_invalid = re.compile(r'^\s*TMOUT=(0+|9[0-9][1-9]|9[1-9][0-9]|[1-9]\d{3,})\b')

        for file in target_files:
            if not os.path.exists(file):
                continue

            with open(file, "r") as f:
                for line in f:
                    s = line.strip()

                    if re_tmout_valid.search(s):
                        found_valid = True
                    if re_tmout_invalid.search(s):
                        found_invalid = True
                    
                    if re_tmout_readonly.search(s):
                        readonly_ok = True

                    if re_tmout_export.search(s):
                        export_ok = True

        if found_valid and readonly_ok and export_ok and not found_invalid:
            return True, "TMOUT CIS'e uygun yapılandırılmış."

        return False, "TMOUT yapılandırması eksik veya hatalı."

    except Exception as e:
        return False, f"Hata: {str(e)}"


def apply_ensure_shell_timeout(username=None, param=None):
    """
    CIS 5.4.3.2 uyumlu TMOUT yapılandırması uygular.
    Tüm TMOUT ayarlarını /etc/profile.d/timeout.sh dosyasında güvenli şekilde toplar.
    """
    try:
        ok, _ = check_ensure_shell_timeout()
        if ok:
            return True, "TMOUT zaten CIS'e uygun."

        timeout_file = "/etc/profile.d/timeout.sh"

        lines = [
            "TMOUT=900\n",
            "readonly TMOUT\n",
            "export TMOUT\n"
        ]

        with open(timeout_file, "w") as f:
            f.writelines(lines)

        return True, "TMOUT değeri CIS uyumlu şekilde /etc/profile.d/timeout.sh içine yazıldı."

    except Exception as e:
        return False, f"Hata: {str(e)}"



def check_umask():
    """
    CIS 5.4.3.3 - Ensure default user umask is configured (FULL CIS COMPLIANT)
    """
    try:
        config_files = [
            "/etc/profile",
            "/etc/bashrc",
            "/etc/bash.bashrc",
            "/etc/login.defs",
            "/etc/default/login",
            "/etc/pam.d/postlogin",
        ]

        profile_d = "/etc/profile.d"
        if os.path.isdir(profile_d):
            for f in os.listdir(profile_d):
                if f.endswith(".sh"):
                    config_files.append(os.path.join(profile_d, f))

        # CIS'e göre güvenli numeric umask: 027, 037, 047, 057, 067, 077
        SAFE_NUMERIC = {f"0{a}{b}7" for a in range(0, 8) for b in range(2, 8)}
        SAFE_NUMERIC.update({"027", "037", "047", "057", "067", "077"})

        insecure_entries = []
        valid_found = False

        for file_path in config_files:
            if not os.path.exists(file_path):
                continue

            with open(file_path, "r") as f:
                for line in f:
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue

                    # Numeric umask (027, 037, 077...)
                    if re.match(r"^\s*umask\s+[0-7]{3}$", text):
                        val = text.split()[1]
                        if val in SAFE_NUMERIC:
                            valid_found = True
                            logger.info(f"[CHECK] Güvenli umask bulundu: {file_path} -> {val}")
                        else:
                            insecure_entries.append(f"{file_path}: {val}")
                        continue

                    # Symbolic umask (u=rwx,g=rx,o=)
                    if re.match(r"^\s*umask\s+u=.*", text):
                        # CIS'e göre o= kısmı boş veya sadece --- olmalı (rw* kabul edilmez)
                        if "o=" in text and not any(x in text for x in ["o=w", "o=rw", "o=rwx"]):
                            valid_found = True
                            logger.info(f"[CHECK] Güvenli symbolic umask: {file_path} -> {text}")
                        else:
                            insecure_entries.append(f"{file_path}: {text}")

        if insecure_entries:
            return False, "Zayıf umask ayarları bulundu: " + ", ".join(insecure_entries)

        if not valid_found:
            return False, "Hiçbir güvenli umask bulunamadı."

        return True, "Varsayılan umask doğru yapılandırılmış."

    except Exception as e:
        logger.error(f"[CHECK][UMASK] Hata: {e}")
        return False, str(e)



def apply_umask(username=None, param=None):
    """
    CIS 5.4.3.3 - Ensure default user umask is configured (FULL CIS COMPLIANT)
    """
    try:
        desired_umask = (param or {}).get("value", "027")

        # PAM tarafındaki umask ayarlarını kaldır (CIS gereği shell override etmemeli)
        pam_file = "/etc/pam.d/postlogin"
        if os.path.exists(pam_file):
            run_command(["bash", "-c",
                        "sed -i 's/^.*pam_umask.so.*umask=.*$/# &/' /etc/pam.d/postlogin"])

        # Shell dosyalarındaki tüm eski umask tanımlarını yorum satırı yapar
        for path in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
                     "/etc/login.defs", "/etc/default/login"]:
            if os.path.exists(path):
                run_command(["bash", "-c", f"sed -i 's/^umask/#&/' {path}"])

        # /etc/profile.d içine merkez tek bir umask tanımı oluşturur
        umask_file = "/etc/profile.d/50-systemwide_umask.sh"
        with open(umask_file, "w") as f:
            f.write(f"umask {desired_umask}\n")

        logger.info(f"[APPLY] Sistem-wide umask {desired_umask} olarak ayarlandı.")
        return True, f"umask {desired_umask} olarak ayarlandı."

    except Exception as e:
        msg = f"UMASK APPLY ERROR: {e}"
        logger.error(msg)
        return False, msg