###############################################################################################################################
###                                                                                                                         ###
###                                             CIS SSHD GÜVENLİK AYARLARI                                                  ###
###                                                                                                                         ###
###############################################################################################################################


import os
import glob
import stat
import shutil
import re


from utils import run_command, get_username, get_groupname, get_include_paths, get_all_sshd_config_files
from logger import logger

SSHD_CONFIG = "/etc/ssh/sshd_config"


def check_sshd_config_permissions():
    """
    CIS 5.1.1 - Ensure permissions on /etc/ssh/sshd_config and related files are configured.
    Beklenen: 600 veya daha kısıtlı, root:root sahiplik.
    """
    files_to_check = get_all_sshd_config_files()
    errors = []
    correct = []

    for f in files_to_check:
        try:
            st = os.stat(f)
            perms = oct(st.st_mode & 0o777)
            user = get_username(st.st_uid)
            group = get_groupname(st.st_gid)

            if int(perms, 8) > 0o600 or user != "root" or group != "root":
                errors.append(f"{f}: mode={perms}, owner={user}, group={group}")
            else:
                correct.append(f"{f}: mode={perms}, owner={user}, group={group}")
        except Exception as e:
            errors.append(f"{f} kontrol edilemedi: {str(e)}")

    if errors:
        return False, "SSH config izin hataları: " + "; ".join(errors)
    else:
        return True, "Tüm SSH config dosyaları doğru ayarlanmış."


def apply_sshd_config_permissions(username=None, param=None):
    """
    CIS 5.1.1 - Uygulama fonksiyonu: yanlış izinleri düzelt.
    """
    try:
        ok, msg = check_sshd_config_permissions()
        if ok:
            return True, msg

        files_to_fix = get_all_sshd_config_files()
        fixed = []
        failed = []

        for f in files_to_fix:
            try:
                run_command(["chmod", "600", f])
                run_command(["chown", "root:root", f])

                st = os.stat(f)
                perms = oct(st.st_mode & 0o777)
                user = get_username(st.st_uid)
                group = get_groupname(st.st_gid)

                if int(perms, 8) <= 0o600 and user == "root" and group == "root":
                    fixed.append(f"{f} düzeltildi (mode={perms}, owner={user}, group={group})")
                else:
                    failed.append(f"{f} düzeltilemedi (mode={perms}, owner={user}, group={group})")

            except Exception as e:
                failed.append(f"{f} hata: {str(e)}")

        if failed:
            return False, "Bazı dosyalar düzeltilemedi: " + "; ".join(failed)
        else:
            return True, "Tüm SSH config dosyaları başarıyla düzeltildi: " + "; ".join(fixed)

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.1][APPLY] {msg}")
        return False, f"SSH config izin düzeltme hatası: {msg}"


def find_ssh_private_host_keys():
    """ /etc/ssh altındaki tüm private host key dosyalarını bul """
    key_files = []
    for f in glob.glob("/etc/ssh/*"):
        try:
            # ssh-keygen ile gerçekten private key mi kontrol et
            ok, _ = run_command(["ssh-keygen", "-lf", f])
            if ok:
                # dosya tipini kontrol et
                ok2, file_out = run_command(["file", f])
                if ok2 and "private key" in file_out.lower():
                    key_files.append(f)
        except Exception:
            continue
    return key_files


def check_ssh_private_host_key_permissions():
    """
    CIS 5.1.2 - Kontrol fonksiyonu
    SSH private host key dosyalarının izin ve sahipliklerini kontrol eder.
    """
    errors = []
    correct = []
    key_files = find_ssh_private_host_keys()

    # ssh_keys veya _ssh grubunu bul
    ssh_group = None
    with open("/etc/group") as f:
        for line in f:
            if line.split(":")[0] in ["ssh_keys", "_ssh"]:
                ssh_group = line.split(":")[0]
                break

    for f in key_files:
        try:
            st = os.stat(f)
            perms = oct(st.st_mode & 0o777)
            user = get_username(st.st_uid)
            group = get_groupname(st.st_gid)

            # grup ssh_keys ise izin <= 0640, değilse izin <= 0600
            if group == ssh_group:
                max_mode = 0o640
            else:
                max_mode = 0o600

            if int(perms, 8) > max_mode or user != "root" or (group not in ["root", ssh_group]):
                errors.append(f"{f}: mode={perms}, owner={user}, group={group}")
            else:
                correct.append(f"{f}: mode={perms}, owner={user}, group={group}")
        except Exception as e:
            errors.append(f"{f} kontrol edilemedi: {str(e)}")

    if errors:
        return False, "SSH private host key izin hataları: " + "; ".join(errors)
    else:
        return True, "Tüm SSH private host key dosyaları doğru ayarlanmış."


def apply_ssh_private_host_key_permissions(username=None, param=None):
    """
    CIS 5.1.2 - Uygulama fonksiyonu
    SSH private host key dosyalarının izin ve sahipliklerini düzeltir.
    """
    try:
        ok, msg = check_ssh_private_host_key_permissions()
        if ok:
            logger.info("SSH private host key dosyaları zaten doğru ayarlanmış.")
            return True, msg

        fixed, failed = [], []
        key_files = find_ssh_private_host_keys()


        ssh_group = None
        with open("/etc/group") as f:
            for line in f:
                if line.split(":")[0] in ["ssh_keys", "_ssh"]:
                    ssh_group = line.split(":")[0]
                    break

        for f in key_files:
            try:
                st = os.stat(f)
                group = get_groupname(st.st_gid)

                if group == ssh_group:
                    run_command(["chmod", "640", f])
                    run_command(["chown", f"root:{ssh_group}", f])
                else:
                    run_command(["chmod", "600", f])
                    run_command(["chown", "root:root", f])

                fixed.append(f"{f} düzeltildi")
            except Exception as e:
                failed.append(f"{f} hata: {str(e)}")


        ok_after, msg_after = check_ssh_private_host_key_permissions()
        if ok_after and not failed:
            logger.info("Tüm SSH private host key dosyaları başarıyla düzeltildi.")
            return True, "Düzeltildi: " + "; ".join(fixed)
        elif ok_after:
            logger.warning("Bazı SSH private host key dosyaları düzeltilemedi: " + "; ".join(failed))
            return True, "Kısmen düzeltildi: " + "; ".join(fixed) + " | Hatalar: " + "; ".join(failed)
        else:
            logger.error("Düzeltme sonrası hâlâ hatalar var: " + msg_after)
            return False, "Düzeltme sonrası hâlâ hatalar var: " + msg_after

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.2][APPLY] {msg}")
        return False, f"SSH private host key izin düzeltme hatası: {msg}"



def find_ssh_public_host_keys():
    """ /etc/ssh altındaki tüm public host key (*.pub) dosyalarını bul. """
    return glob.glob("/etc/ssh/*.pub")


def check_ssh_public_host_key_permissions():
    """
    CIS 5.1.3 – Public host key dosyaları root:root ve en fazla 0644 olmalı.
    Herhangi bir değişiklik yapmaz.
    """
    errors, correct = [], []
    key_files = find_ssh_public_host_keys()

    if not key_files:
        return True, "Public host key (.pub) dosyası bulunamadı."

    for f in key_files:
        try:
            st = os.stat(f)
            mode = stat.S_IMODE(st.st_mode)
            owner = get_username(st.st_uid)
            group = get_groupname(st.st_gid)

            if mode <= 0o644 and owner == "root" and group == "root":
                correct.append(f"{f} (mode={oct(mode)}, owner={owner}, group={group})")
            else:
                errors.append(f"{f} (mode={oct(mode)}, owner={owner}, group={group})")
        except Exception as e:
            errors.append(f"{f} kontrol edilemedi: {e}")

    if errors:
        return False, "Hatalı public host key izin/sahiplikleri: " + "; ".join(errors)
    return True, "Tüm public host key dosyaları doğru yapılandırılmış."


def apply_ssh_public_host_key_permissions(username=None, param=None):
    """
    CIS 5.1.3 – Uygulama fonksiyonu.
    Önce check çağrılır; uygunsuzluk varsa chmod/chown ile düzeltilir,
    ardından tekrar check edilerek doğrulanır.
    """
    try:
        ok, msg = check_ssh_public_host_key_permissions()
        if ok:
            logger.info(f"SSH public host key dosyaları zaten doğru ayarlanmış. {msg}")    
            return True, msg

        fixed, failed = [], []
        key_files = find_ssh_public_host_keys()

        for f in key_files:
            try:
                # Hedef durum: 0644, root:root
                ok1, out1 = run_command(["chmod", "644", f])
                ok2, out2 = run_command(["chown", "root:root", f])

                if not ok1:
                    failed.append(f"{f}: chmod 644 başarısız ({out1})")
                    continue
                if not ok2:
                    failed.append(f"{f}: chown root:root başarısız ({out2})")
                    continue

                fixed.append(f"{f}: 0644 ve root:root uygulandı")
            except Exception as e:
                failed.append(f"{f}: düzeltme hatası ({e})")

        ok_after, msg_after = check_ssh_public_host_key_permissions()
        if ok_after and not failed:
            logger.info("Tüm SSH public host key dosyaları başarıyla düzeltildi.")
            return True, "Düzeltildi: " + "; ".join(fixed)
        elif ok_after:
            logger.warning("Bazı SSH public host key dosyaları düzeltilemedi: " + "; ".join(failed))
            return True, "Düzeltildi (kısmen): " + "; ".join(fixed) + " | Hatalar: " + "; ".join(failed)
        else:
            logger.error("Düzeltme sonrası hâlâ hatalar var: " + msg_after)
            return False, "Düzeltme sonrası hâlâ hatalar var: " + msg_after + " | İşlemler: " + "; ".join(fixed) + " | Hatalar: " + "; ".join(failed)

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.3][APPLY] {msg}")
        return False, f"SSH public host key izin düzeltme hatası: {msg}"



def check_sshd_access():
    """
    CIS 5.1.4: SSH erişim kontrolü denetimi.
    En az bir tane allow/deny parametresi ayarlı olmalı.
    """
    try:
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        matches = re.findall(r'^(allowusers|allowgroups|denyusers|denygroups)\s+.+$', output, re.MULTILINE)
        if not matches:
            return False, "Herhangi bir AllowUsers/AllowGroups/DenyUsers/DenyGroups ayarı bulunamadı."

        return True, f"Erişim kontrolü ayarlı: {', '.join(set(matches))}"

    except Exception as e:
        return False, f"Kontrol hatası: {str(e)}"


def apply_sshd_access(username=None, param=None):
    """
    CIS 5.1.4: SSH erişim kısıtlamalarını uygula.
    Parametreler:
        param["AllowUsers"]  = "user1 user2"   (boş olabilir)
        param["AllowGroups"] = "group1 group2"
        param["DenyUsers"]   = "user3"
        param["DenyGroups"]  = "group3 group4"
    """
    try:
        param = param or {}

        keys = ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]
        non_empty = {k: v for k, v in param.items() if v}

        if not non_empty:
            return check_sshd_access()

        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            if not any(line.strip().lower().startswith(k.lower()) for k in keys):
                new_lines.append(line)

        for key, value in non_empty.items():
            new_lines.append(f"{key} {value}\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        return check_sshd_access()

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.4][APPLY] {msg}")
        return False, f"SSH erişim kısıtlaması hata: {msg}"




BANNER_FILE = "/etc/issue.net"

def check_sshd_banner():
    """
    CIS 5.1.5 - SSHD Banner kontrolü
    """
    try:
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        # output.stdout yerine direkt output kullan
        banner_line = [line for line in output.splitlines() if line.strip().lower().startswith("banner")]

        if not banner_line:
            return False, "Banner ayarı bulunamadı."

        key, path = banner_line[0].split(maxsplit=1)
        if not os.path.exists(path):
            return False, f"Banner dosyası mevcut değil: {path}"

        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return False, "Banner dosyası boş."

        forbidden_tokens = ["\\m", "\\r", "\\s", "\\v"]
        for token in forbidden_tokens:
            if token in content:
                return False, f"Banner dosyası uygunsuz içerik içeriyor: {token}"

        return True, f"Banner ayarı doğru: {path}"

    except Exception as ex:
        return False, f"Hata: {ex}"


def apply_sshd_banner(username=None, param=None):
    """
    CIS 5.1.5 - SSHD Banner uygula
    Parametre:
        {
          "BannerMessage": "Authorized users only. All activity may be monitored."
        }
    """
    try:

        check_ok, check_msg = check_sshd_banner()
        if check_ok:
            return True, f"Banner zaten doğru ayarlanmış: {check_msg}"

        message = param.get("BannerMessage", "").strip()
        if not message:
            return False, "Banner mesajı parametre olarak verilmedi."

        with open(BANNER_FILE, "w", encoding="utf-8") as f:
            f.write(message + "\n")

        updated_lines = []
        banner_set = False

        if os.path.exists(SSHD_CONFIG):
            with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().lower().startswith("banner "):
                        updated_lines.append(f"Banner {BANNER_FILE}\n")
                        banner_set = True
                    else:
                        updated_lines.append(line)

        if not banner_set:
            updated_lines.insert(0, f"Banner {BANNER_FILE}\n")

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)

        success, output = run_command(["systemctl", "restart", "sshd"])

        if not success:
            return False, f"systemctl restart çalıştırılamadı: {output}"
            
        return check_sshd_banner()

    except Exception as ex:
        msg = f"Hata: {str(ex)}"
        logger.error(f"Banner ayarlanırken hata: {msg}")
        return False, f"Banner ayarlanırken hata: {msg}"



# CIS'e göre varsayılan güvenli cipher listesi
DEFAULT_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

# CIS'e göre zayıf ciphers listesi
WEAK_CIPHERS = [
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
    "chacha20-poly1305@openssh.com"
]


def check_sshd_ciphers(username=None, param=None):
    """
    CIS 5.1.6 - Ensure sshd Ciphers are configured
    """
    try:
        expected_ciphers = param.get("ciphers") if param else DEFAULT_CIPHERS

        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        current_ciphers = None
        for line in output.splitlines():   # <-- sadece splitlines(), decode yok
            if line.strip().startswith("ciphers"):
                current_ciphers = line.split(None, 1)[1].strip()
                break

        if not current_ciphers:
            return False, "Ciphers parametresi sshd -T çıktısında bulunamadı."

        weak_found = [w for w in WEAK_CIPHERS if w in current_ciphers.split(",")]
        if weak_found:
            return False, f"Zayıf cipher(lar) bulundu: {', '.join(weak_found)}"

        if current_ciphers == expected_ciphers:
            return True, f"Ciphers doğru yapılandırılmış: {current_ciphers}"
        else:
            return False, f"Mevcut Ciphers: {current_ciphers}, beklenen: {expected_ciphers}"

    except Exception as e:
        return False, f"Hata (check_sshd_ciphers): {e}"



def apply_sshd_ciphers(username=None, param=None):
    """
    CIS 5.1.6 - Apply sshd Ciphers configuration
    """
    try:
        new_ciphers = param.get("ciphers") if param else DEFAULT_CIPHERS

        backup_file = f"{SSHD_CONFIG}.bak"
        shutil.copy2(SSHD_CONFIG, backup_file)

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        updated_lines = []
        ciphers_set = False
        for line in lines:
            if line.strip().startswith("Ciphers"):
                updated_lines.append(f"Ciphers {new_ciphers}\n")
                ciphers_set = True
            else:
                updated_lines.append(line)

        if not ciphers_set:
            updated_lines.append(f"\nCiphers {new_ciphers}\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(updated_lines)

        # Config test (syntax check)
        success, output = run_command(["sshd", "-t"])
        if not success:
            shutil.copy2(backup_file, SSHD_CONFIG)
            return False, f"Config test hatası: {output}"

        # Servisi yeniden başlat
        success, output = run_command(["systemctl", "restart", "sshd"])
        if not success:
            shutil.copy2(backup_file, SSHD_CONFIG)
            return False, f"sshd restart başarısız: {output}"

        # Doğrulama
        ok, msg = check_sshd_ciphers(param={"ciphers": new_ciphers})
        if ok:
            return True, f"Ciphers başarıyla güncellendi: {msg}"
        else:
            return False, f"Ciphers yazıldı ama doğrulama başarısız: {msg}"

    except Exception as e:
        logger.error(f"Hata (apply_sshd_ciphers): {e}")
        return False, f"Hata (apply_sshd_ciphers): {e}"



def read_sshd_config():
    """Konfigürasyon dosyasını oku"""
    try:
        with open(SSHD_CONFIG, "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""

def write_sshd_config(content):
    """Konfigürasyon dosyasını yaz"""
    with open(SSHD_CONFIG, "w") as f:
        f.write(content)

def reload_sshd():
    """sshd servisini yeniden yükle"""
    success, output = run_command(["systemctl", "reload", "sshd"])
    if not success:
        return False, f"sshd reload çalıştırılamadı: {output}"
    return True, "sshd reload edildi."

def check_ssh_client_alive(param):
    """
    CIS 5.1.7 kontrolü:
    ClientAliveInterval ve ClientAliveCountMax değerlerini doğrula
    """
    desired_interval = param.get("ClientAliveInterval")
    desired_count = param.get("ClientAliveCountMax")

    success, output = run_command(["sshd", "-T"])
    if not success:
        return False, f"sshd -T çalıştırılamadı: {output}"

    current = {}
    for line in output.splitlines():
        if line.startswith("clientaliveinterval"):
            current["ClientAliveInterval"] = int(line.split()[1])
        elif line.startswith("clientalivecountmax"):
            current["ClientAliveCountMax"] = int(line.split()[1])

    # CIS gereği > 0 olmalı
    if current.get("ClientAliveInterval", 0) <= 0:
        return False, f"ClientAliveInterval {current.get('ClientAliveInterval')} (0 veya daha az olmamalı)"
    if current.get("ClientAliveCountMax", 0) <= 0:
        return False, f"ClientAliveCountMax {current.get('ClientAliveCountMax')} (0 olmamalı)"

    # Parametrelerle uyuşuyor mu?
    if desired_interval is not None and current["ClientAliveInterval"] != desired_interval:
        return False, f"ClientAliveInterval beklenen {desired_interval}, mevcut {current['ClientAliveInterval']}"
    if desired_count is not None and current["ClientAliveCountMax"] != desired_count:
        return False, f"ClientAliveCountMax beklenen {desired_count}, mevcut {current['ClientAliveCountMax']}"

    return True, "ClientAlive ayarları doğru yapılandırılmış."



def apply_ssh_client_alive(username=None, param=None):
    """
    CIS 5.1.7 düzeltme:
    ClientAliveInterval ve ClientAliveCountMax değerlerini ayarla
    """
    try:
        status, message = check_ssh_client_alive(param)
        if status:
            return True, f"Değişiklik gerekmiyor: {message}"

        interval = param.get("ClientAliveInterval")
        count = param.get("ClientAliveCountMax")

        if interval is None and count is None:
            return False, "Parametreler boş geldi."

        config = read_sshd_config()

        # Match blokları varsa, onların üstüne ekle
        match_pos = re.search(r"^\s*Match\b", config, re.MULTILINE)
        insert_point = match_pos.start() if match_pos else len(config)

        new_lines = []
        if interval is not None:
            if re.search(r"^\s*ClientAliveInterval", config, re.MULTILINE):
                config = re.sub(r"^\s*ClientAliveInterval.*",
                                f"ClientAliveInterval {interval}",
                                config, flags=re.MULTILINE)
            else:
                new_lines.append(f"ClientAliveInterval {interval}")
        if count is not None:
            if re.search(r"^\s*ClientAliveCountMax", config, re.MULTILINE):
                config = re.sub(r"^\s*ClientAliveCountMax.*",
                                f"ClientAliveCountMax {count}",
                                config, flags=re.MULTILINE)
            else:
                new_lines.append(f"ClientAliveCountMax {count}")

        if new_lines:
            config = config[:insert_point] + "\n".join(new_lines) + "\n" + config[insert_point:]

        write_sshd_config(config)
        return reload_sshd()
    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.7][APPLY] {msg}")
        return False, f"SSH ClientAlive ayar düzeltme hatası: {msg}"



def check_sshd_disableforwarding():
    """
    CIS 5.1.8 - SSH DisableForwarding kontrol fonksiyonu.
    Beklenen: DisableForwarding yes
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        if line.lower().startswith("disableforwarding"):
            value = line.split()[1].lower()
            if value == "yes":
                return True, "DisableForwarding zaten 'yes' olarak ayarlanmış."
            else:
                return False, f"DisableForwarding mevcut değer: {value}"

    return False, "DisableForwarding parametresi bulunamadı, varsayılan 'no' olabilir."


def apply_sshd_disableforwarding(username=None, param=None):
    """
    CIS 5.1.8 - SSH DisableForwarding uygulama fonksiyonu.
    """
    ok, msg = check_sshd_disableforwarding()
    if ok:
        return True, f"Her şey zaten doğru: {msg}"

    try:
        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if line.strip().lower().startswith("disableforwarding"):
                new_lines.append("DisableForwarding yes\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            insert_index = 0
            for i, line in enumerate(new_lines):
                if line.strip().lower().startswith(("include", "match")):
                    insert_index = i
                    break
            new_lines.insert(insert_index, "DisableForwarding yes\n")
        
        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        ok, msg = check_sshd_disableforwarding()
        if ok:
            return True, "DisableForwarding parametresi başarıyla 'yes' olarak ayarlandı."
        else:
            return False, f"Düzeltme uygulandı ama sorun devam ediyor: {msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.8][APPLY] {msg}")   
        return False, f"DisableForwarding parametresi düzenlenemedi: {msg}"



def check_sshd_gssapiauthentication():
    """
    CIS 5.1.9 - Kontrol fonksiyonu
    SSHD GSSAPIAuthentication ayarının 'no' olduğunu doğrular.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        if line.strip().startswith("gssapiauthentication"):
            value = line.strip().split()[-1].lower()
            if value == "no":
                return True, "GSSAPIAuthentication doğru şekilde 'no' olarak ayarlanmış."
            else:
                return False, f"GSSAPIAuthentication hatalı: {value}"

    return False, "GSSAPIAuthentication parametresi bulunamadı."


def apply_sshd_gssapiauthentication(username=None, param=None):
    """
    CIS 5.1.9 - Uygulama fonksiyonu
    SSHD yapılandırmasında GSSAPIAuthentication 'no' olarak ayarlanır.
    """
    ok, msg = check_sshd_gssapiauthentication()
    if ok:
        return True, msg

    backup_file = SSHD_CONFIG + ".bak"

    try:
        # yedek al
        shutil.copy2(SSHD_CONFIG, backup_file)

        lines = []
        inserted = False
        with open(SSHD_CONFIG, "r") as f:
            for line in f:
                # Eğer Include veya Match satırına denk gelmeden önce eklenmemişse buraya ekle
                if not inserted and (line.strip().startswith("Include") or line.strip().startswith("Match")):
                    lines.append("GSSAPIAuthentication no\n")
                    inserted = True
                lines.append(line)

        # Eğer hiç eklenmediyse en sona ekle
        if not inserted:
            lines.append("GSSAPIAuthentication no\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(lines)

        # sshd yapılandırmasını yeniden yüklemeden önce test et
        ok, output = run_command(["sshd", "-t"])
        if not ok:
            # Hatalı config → geri dön
            shutil.copy2(backup_file, SSHD_CONFIG)
            return False, f"Config test başarısız: {output}. Yedek geri yüklendi."

        run_command(["systemctl", "reload", "sshd"])

        ok, msg = check_sshd_gssapiauthentication()
        if ok:
            return True, "GSSAPIAuthentication başarıyla 'no' olarak ayarlandı."
        else:
            return False, "Değişiklik yapıldı ama kontrol başarısız: " + msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.9][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_sshd_hostbasedauthentication():
    """
    CIS 5.1.10 - Check that sshd HostbasedAuthentication is 'no'.
    Uses `sshd -T` output to verify. Returns (bool, message).
    Note: If Match blocks are used and you need to test for a specific
    connection context, extend to call `sshd -T -C ...`.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("hostbasedauthentication"):
            parts = line.split()
            if len(parts) >= 2 and parts[-1].lower() == "no":
                return True, "HostbasedAuthentication doğru: no"
            else:
                value = parts[-1] if len(parts) >= 2 else "(belirsiz)"
                return False, f"HostbasedAuthentication yanlış: {value}"
    return False, "HostbasedAuthentication ayarı bulunamadı (sshd -T çıktısında yok)."


def apply_sshd_hostbasedauthentication(username=None, param=None):
    """
    CIS 5.1.10 - Ensure HostbasedAuthentication is disabled.
    - Değilse /etc/ssh/sshd_config yedeklenir ve:
        * Eğer mevcut HostbasedAuthentication satırı varsa ve Include/Match'den önce değilse,
          dosyanın Include/Match satırlarının hemen önüne "HostbasedAuthentication no" eklenir.
        * Eğer mevcut HostbasedAuthentication satırı varsa ve zaten Include/Match'den önceyse,
          o satırın değeri "no" olacak şekilde güncellenir.
        * Eğer hiç yoksa Include/Match satırlarının önüne eklenir (veya dosya boşsa en üst).
    """


    backup = SSHD_CONFIG + ".cisbak"

    ok, msg = check_sshd_hostbasedauthentication()
    if ok:
        return True, msg

    if not os.path.exists(SSHD_CONFIG):
        return False, f"{SSHD_CONFIG} bulunamadı."

    try:
        shutil.copy2(SSHD_CONFIG, backup)

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = None
        for idx, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue
            s_low = s.lower()
            if s_low.startswith("include ") or s_low.startswith("match "):
                insert_index = idx
                break
        if insert_index is None:
            insert_index = 0

        # dosyada ilk HostbasedAuthentication var mı ve indeksi nedir?
        first_hba_index = None
        pattern = re.compile(r'^\s*hostbasedauthentication\b', re.IGNORECASE)
        for idx, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if pattern.match(s):
                first_hba_index = idx
                break

        new_lines = list(lines)

        if first_hba_index is None:
            new_lines.insert(insert_index, "HostbasedAuthentication no\n")
        else:
            # var => eğer zaten insert_index'den önceyse onu güncelle; değilse yeni bir satır ekle insert_index'e
            if first_hba_index <= insert_index:
                # korumak için orijinal leading whitespace al
                leading = re.match(r'^(\s*)', lines[first_hba_index]).group(1)
                new_lines[first_hba_index] = f"{leading}HostbasedAuthentication no\n"
            else:
                # mevcuttan sonra; Insert kullanarak öncelikli hale getir
                new_lines.insert(insert_index, "HostbasedAuthentication no\n")

        with open(cfg, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            shutil.copy2(backup, cfg)
            return False, f"sshd -t başarısız: {out_test}. Orijinal dosya geri yüklendi."

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_hostbasedauthentication()
        if ok_final:
            return True, "HostbasedAuthentication başarıyla 'no' yapıldı."
        else:
            return False, f"Değişiklik uygulandı ama doğrulama başarısız: {msg_final}"

    except Exception as e:
        try:
            if os.path.exists(backup):
                shutil.copy2(backup, cfg)
        except Exception:
            pass
        msg = f"Hata: {str(e)}"
        logger.error(f"Hata: {msg}")
        return False, f"Uygulama sırasında hata: {msg}"



def check_sshd_ignorerhosts():
    """
    CIS 5.1.11 - SSH IgnoreRhosts kontrol fonksiyonu.
    Beklenen: IgnoreRhosts yes
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        if line.lower().startswith("ignorerhosts"):
            value = line.split()[1].lower()
            if value == "yes":
                return True, "IgnoreRhosts zaten 'yes' olarak ayarlanmış."
            else:
                return False, f"IgnoreRhosts mevcut değer: {value}"

    return False, "IgnoreRhosts parametresi bulunamadı, varsayılan 'no' olabilir."


def apply_sshd_ignorerhosts(username=None, param=None):
    """
    CIS 5.1.11 - SSH IgnoreRhosts uygulama fonksiyonu.
    Önce check çalıştırılır, gerekiyorsa düzeltme yapılır.
    """
    ok, msg = check_sshd_ignorerhosts()
    if ok:
        return True, f"Her şey zaten doğru: {msg}"

    
    try:
        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if line.strip().lower().startswith("ignorerhosts"):
                new_lines.append("IgnoreRhosts yes\n")
                found = True
            else:
                new_lines.append(line)
        if not found:

            insert_index = 0
            for i, line in enumerate(new_lines):
                if line.strip().lower().startswith(("include", "match")):
                    insert_index = i
                    break
            new_lines.insert(insert_index, "IgnoreRhosts yes\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        ok, msg = check_sshd_ignorerhosts()
        if ok:
            return True, "IgnoreRhosts parametresi başarıyla 'yes' olarak ayarlandı."
        else:
            return False, f"Düzeltme uygulandı ama sorun devam ediyor: {msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.11][APPLY] {msg}")
        return False, f"IgnoreRhosts parametresi düzenlenemedi: {msg}"



WEAK_KEX_ALGORITHMS = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
]


def check_sshd_kexalgorithms():
    """
    CIS 5.1.12 - Kontrol fonksiyonu
    SSHD KexAlgorithms ayarının zayıf algoritmaları engelleyip engellemediğini kontrol eder.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    weak_found = []
    for algo in WEAK_KEX_ALGORITHMS:
        if re.search(rf"\b{algo}\b", output):
            weak_found.append(algo)

    if weak_found:
        return False, f"Zayıf KexAlgorithms kullanılıyor: {', '.join(weak_found)}"

    return True, "KexAlgorithms doğru yapılandırılmış (zayıf algoritma yok)."


def apply_sshd_kexalgorithms(username=None, param=None):
    """
    CIS 5.1.12 - Uygulama fonksiyonu
    sshd_config içine zayıf KexAlgorithms algoritmalarını disable edecek satırı ekler/düzenler.
    """
    ok, msg = check_sshd_kexalgorithms()
    if ok:
        return True, f"Her şey zaten doğru: {msg}"

    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        disable_line = "KexAlgorithms -" + ",".join(WEAK_KEX_ALGORITHMS) + "\n"

        found = False
        new_lines = []
        for line in lines:
            if line.strip().lower().startswith("kexalgorithms"):
                new_lines.append(disable_line)
                found = True
            else:
                new_lines.append(line)

        if not found:
            inserted = False
            for i, line in enumerate(new_lines):
                if line.strip().lower().startswith(("include", "match")):
                    new_lines.insert(i, disable_line)
                    inserted = True
                    break
            if not inserted:
                new_lines.append(disable_line)

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        # Config test
        ok, out = run_command(["sshd", "-t"])
        if not ok:
            return False, f"sshd config test başarısız: {out}"

        # Son doğrulama
        return check_sshd_kexalgorithms()

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.12][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_sshd_logingracetime():
    """CIS 5.1.13 - Check LoginGraceTime"""
    conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
    valid = True
    messages = []

    for conf_file in conf_files:
        try:
            with open(conf_file) as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean.lower().startswith("logingracetime"):
                        try:
                            value = int(line_clean.split()[1])
                            if 1 <= value <= 60:
                                messages.append(f"{conf_file}: LoginGraceTime uygun ({value})")
                            else:
                                valid = False
                                messages.append(f"{conf_file}: LoginGraceTime hatalı ({value})")
                        except (IndexError, ValueError):
                            valid = False
                            messages.append(f"{conf_file}: LoginGraceTime okunamadı ({line_clean})")
                        break  # İlk occurrence geçerlidir
        except Exception as e:
            valid = False
            messages.append(f"{conf_file} okunamadı: {str(e)}")

    if valid:
        return True, "Tüm dosyalarda LoginGraceTime uygun. " + "; ".join(messages)
    else:
        return False, "LoginGraceTime hatalı: " + "; ".join(messages)


def apply_sshd_logingracetime(username=None, param=None):
    """
    CIS 5.1.13 - Apply LoginGraceTime
    - param: dict, örn. {"LoginGraceTime": 60}
    """
    try:
        param = param or {}
        value = int(param.get("LoginGraceTime", 60))

        check_ok, msg = check_sshd_logingracetime()
        if check_ok and "hatalı" not in msg:
            return True, f"Zaten uygun: {msg}"

        conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        fixed_files = []
        failed_files = []

        for conf_file in conf_files:
            try:
                run_command(["sudo", "cp", conf_file, f"{conf_file}.bak"])

                run_command(["sudo", "sed", "-i", "/^\\s*LoginGraceTime/d", conf_file])

                run_command(["sudo", "sed", "-i", f"1iLoginGraceTime {value}", conf_file])
                fixed_files.append(conf_file)
            except Exception as e:
                failed_files.append(f"{conf_file} hata: {str(e)}")

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"SSH servisi reload edilemedi: {output}"

        check_ok2, msg2 = check_sshd_logingracetime()
        if check_ok2:
            return True, f"LoginGraceTime başarıyla ayarlandı: {value}. Düzeltme yapılan dosyalar: {fixed_files}"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}. Hatalı dosyalar: {failed_files}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.13][APPLY] {msg}")
        return False, f"LoginGraceTime uygulama hatası: {msg}"



def check_sshd_loglevel(param=None):
    """
    CIS 5.1.14 - Ensure sshd LogLevel is configured (INFO or VERBOSE)
    """
    param = param or {}
    expected_levels = ["INFO", "VERBOSE"]

    try:
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        for line in output.splitlines():
            if line.strip().startswith("loglevel"):
                current_level = line.split()[1].upper()
                if current_level in expected_levels:
                    return True, f"sshd LogLevel uyumlu: {current_level}"
                else:
                    return False, f"sshd LogLevel uyumsuz: {current_level}, beklenen: {expected_levels}"

        return False, "sshd LogLevel ayarı bulunamadı."
    except Exception as e:
        return False, f"Hata (check_sshd_loglevel): {str(e)}"


def apply_sshd_loglevel(username=None, param=None):
    """
    CIS 5.1.14 - Ensure sshd LogLevel is configured
    Parametreler:
        param["level"] = "INFO" veya "VERBOSE"
    """
    param = param or {}
    desired_level = param.get("level", "INFO").upper()

    is_ok, message = check_sshd_loglevel(param)
    if is_ok:
        return True, f"İşlem yapılmadı: {message}"

    valid_levels = ["INFO", "VERBOSE"]
    if desired_level not in valid_levels:
        return False, f"Geçersiz loglevel parametresi: {desired_level}. Sadece {valid_levels} kullanılabilir."

    backup_file = f"{SSHD_CONFIG}.bak"

    try:
        shutil.copy2(SSHD_CONFIG, backup_file)

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        loglevel_set = False
        for line in lines:
            if line.strip().lower().startswith("loglevel") and not loglevel_set:
                new_lines.append(f"LogLevel {desired_level}\n")
                loglevel_set = True
            else:
                new_lines.append(line)

        if not loglevel_set:
            insert_index = 0
            for i, line in enumerate(new_lines):
                if line.strip().lower().startswith(("include", "match")):
                    insert_index = i
                    break
            new_lines.insert(insert_index, f"LogLevel {desired_level}\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        ok, out = run_command(["sshd", "-t"])
        if not ok:
            shutil.copy2(backup_file, SSHD_CONFIG)
            return False, f"sshd config test başarısız: {out}"

        success, output = run_command(["systemctl", "reload", "sshd"])
        if not success:
            return False, f"sshd reload başarısız: {output}"

        ok, msg = check_sshd_loglevel({"level": desired_level})
        if ok:
            return True, f"sshd LogLevel {desired_level} olarak ayarlandı. (Yedek: {backup_file})"
        else:
            return False, f"LogLevel yazıldı ama doğrulama başarısız: {msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.14][APPLY] {msg}")
        return False, msg



BACKUP_CONFIG = "/etc/ssh/sshd_config.bak"

WEAK_MACS = [
    # CIS tarafından zayıf kabul edilenler
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",

    # CVE-2023-48795 kapsamında disable edilmesi önerilen etm MAC’ler
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com"
]

def check_sshd_macs(param):
    """
    CIS 5.1.15 - SSHD MAC algoritmalarını kontrol et.
    """
    param = param or {}
    allowed_macs = param.get("allowed_macs", [])

    success, result = run_command(["sshd", "-T"])
    if not success:
        return False, f"sshd -T çalıştırılamadı: {result}"

    current_macs = []
    for line in result.splitlines():

        if line.strip().startswith("macs"):
            current_macs = line.split()[1].split(",")

    if not current_macs:
        return False, "MACs ayarı bulunamadı."

    for weak in WEAK_MACS:
        if weak in current_macs:
            return False, f"Zayıf MAC bulundu: {weak}"

    if allowed_macs:
        if set(current_macs) != set(allowed_macs):
            return False, f"Mevcut MAC listesi beklenenden farklı. Mevcut: {current_macs}"

    return True, "SSHD MACs ayarı güvenli."



def apply_sshd_macs(username=None, parameters=None):
    """
    CIS 5.1.15 - - Uygulama fonksiyonu
    sshd_config içine güvenli MACs algoritmalarını ekler/düzenler.
    """
    try:

        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        allowed_macs = parameters.get("allowed_macs") if parameters else None
        if not allowed_macs:
            return False, "allowed_macs parametresi bulunamadı."

        # Tek string verilirse listeye dönüştür
        if isinstance(allowed_macs, str):
            allowed_macs = [allowed_macs]

        # MACs satırı hazırla
        macs_line = "MACs " + ",".join(allowed_macs) + "\n"

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if line.strip().startswith("MACs"):
                new_lines.append(macs_line)
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(macs_line)

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        # Konfigürasyon test et
        ok, out = run_command(["sshd", "-t"])
        if not ok:
            return False, f"sshd config test başarısız: {out}"

        # Servisi yeniden başlat
        ok, out = run_command(["systemctl", "restart", "ssh"])
        if not ok:
            return False, f"sshd restart çalıştırılamadı: {out}"

        return True, f"MACs başarıyla uygulandı: {','.join(allowed_macs)}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.13][APPLY] {msg}")
        return False, msg



def check_sshd_maxauthtries():
    """
    CIS 5.1.16 - Check MaxAuthTries
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd konfigürasyonu kontrol edilemedi: {output}"

    for line in output.splitlines():
        if line.lower().startswith("maxauthtries"):
            try:
                value = int(line.split()[1])
                if value <= 4:
                    return True, f"MaxAuthTries uygun: {value}", value
                else:
                    return False, f"MaxAuthTries çok yüksek: {value}", value
            except (ValueError, IndexError):
                return False, f"MaxAuthTries değeri okunamadı: {line}", None

    # Ayar yoksa, varsayılan değer 6'dır ve uygunsuzdur
    return False, "MaxAuthTries ayarı bulunamadı, varsayılan değer 6 ve uygunsuz.", None


def apply_sshd_maxauthtries(username=None, param=None):
    """
    CIS 5.1.16 - Apply MaxAuthTries
    param: dict, örn. {"MaxAuthTries": 3}
    """
    value = int(param.get("MaxAuthTries", 4)) if param else 4

    try:
        check_ok, msg, current_value = check_sshd_maxauthtries()

        # Eğer mevcut değer aynıysa yine de değiştirelim (senin istediğin davranış)
        if check_ok and current_value == value:
            return True, f"Zaten uygun ama gelen parametreyle güncellendi: {value}"

        run_command(["cp", SSHD_CONFIG, f"{SSHD_CONFIG}.bak"])
        run_command(["sudo", "sed", "-i", "/^\\s*MaxAuthTries/d", SSHD_CONFIG])
        run_command(["sudo", "sed", "-i", f"1iMaxAuthTries {value}", SSHD_CONFIG])

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"sshd servisi yeniden yüklenemedi: {output}"

        check_ok2, msg2, _ = check_sshd_maxauthtries()
        if check_ok2:
            return True, f"MaxAuthTries başarıyla ayarlandı: {value}. {msg2}"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.16][APPLY] {msg}")
        return False, f"Hata: {msg}"


def check_sshd_maxsessions():
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        if line.lower().startswith("maxsessions"):
            try:
                value = int(line.split()[1])
                if value <= 10:
                    return True, f"MaxSessions uygun: {value}"
                else:
                    return False, f"MaxSessions çok yüksek: {value}"
            except (ValueError, IndexError):
                return False, f"MaxSessions değeri okunamadı: {line}"

    return False, "MaxSessions ayarı bulunamadı (varsayılan 10)."



def apply_sshd_maxsessions(username=None, param=None):
    """CIS 5.1.17 - Apply MaxSessions 10 veya daha az"""
    try:
        check_ok, msg = check_sshd_maxsessions()
        if check_ok:
            return True, f"Zaten uygun: {msg}"

        maxsessions_value = param.get("maxsessions", 10)

        conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        fixed_files = []
        failed_files = []

        for conf_file in conf_files:
            try:
                run_command(["sudo", "cp", conf_file, f"{conf_file}.bak"])
                run_command(["sudo", "sed", "-i", "/^\\s*MaxSessions/d", conf_file])
                run_command(["sudo", "sed", "-i", f"1iMaxSessions {maxsessions_value}", conf_file])
                fixed_files.append(conf_file)
            except Exception as e:
                failed_files.append(f"{conf_file} hata: {str(e)}")

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"SSH servisi reload edilemedi: {output}"

        check_ok2, msg2 = check_sshd_maxsessions()
        if check_ok2:
            return True, f"MaxSessions başarıyla ayarlandı: {maxsessions_value}. Düzeltme yapılan dosyalar: {fixed_files}"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}. Hatalı dosyalar: {failed_files}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.17][APPLY] {msg}")
        return False, f"MaxSessions uygulama hatası: {msg}"



def check_sshd_maxstartups():
    """
    CIS 5.1.18 - Check MaxStartups
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd konfigürasyonu okunamadı: {output}"

    for line in output.splitlines():
        if line.lower().startswith("maxstartups"):
            try:
                value = line.split()[1]
                parts = value.split(":")
                if len(parts) == 3:
                    start, pct, maxc = map(int, parts)
                    if start <= 10 and pct <= 30 and maxc <= 60:
                        return True, f"MaxStartups uygun: {value}"
                    else:
                        return False, f"MaxStartups çok gevşek: {value}"
                else:
                    return False, f"MaxStartups formatı hatalı: {value}"
            except Exception as e:
                return False, f"MaxStartups okunamadı: {str(e)}"

    # Parametre yoksa varsayılan değer geçerli: 10:30:100 → uyumsuz
    return False, "MaxStartups ayarı yok, varsayılan 10:30:100 uygunsuz."


def apply_sshd_maxstartups(username=None, param=None):
    """
    CIS 5.1.18 - Apply MaxStartups
    param: dict, örn. {"MaxStartups": "10:30:60"}
    """

    check_ok, msg = check_sshd_maxstartups()
    if check_ok:
        return True, f"Zaten uygun: {msg}"

    value = param.get("MaxStartups", "10:30:60") if param else "10:30:60"

    try:

        run_command(["cp", SSHD_CONFIG, f"{SSHD_CONFIG}.bak"])

        run_command(["sudo", "sed", "-i", "/^\\s*MaxStartups/d", SSHD_CONFIG])

        run_command(["sudo", "sed", "-i", f"1iMaxStartups {value}", SSHD_CONFIG])

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"sshd reload başarısız: {output}"

        check_ok2, msg2 = check_sshd_maxstartups()
        if check_ok2:
            return True, f"MaxStartups başarıyla ayarlandı: {value}. {msg2}"
        else:
            return False, f"Ayar sonrası kontrol başarısız: {msg2}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.18][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_sshd_permitemptypasswords():
    """CIS 5.1.19 - Check PermitEmptyPasswords"""
    conf_files = [SSHD_CONFIG] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
    permit_ok = True
    messages = []

    for conf_file in conf_files:
        try:
            with open(conf_file) as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean.startswith("#"):
                        continue
                    if line_clean.lower().startswith("permitemptypasswords"):
                        parts = line_clean.split()
                        value = parts[1].lower() if len(parts) >= 2 else ""
                        if value != "no":
                            permit_ok = False
                            messages.append(f"{conf_file}: PermitEmptyPasswords hatalı ({value})")
                        else:
                            messages.append(f"{conf_file}: PermitEmptyPasswords uygun ({value})")

        except Exception as e:
            permit_ok = False
            messages.append(f"{conf_file} okunamadı: {str(e)}")

    if permit_ok:
        return True, "Tüm dosyalarda PermitEmptyPasswords uygun. " + "; ".join(messages)
    else:
        return False, "PermitEmptyPasswords hatalı: " + "; ".join(messages)



def apply_sshd_permitemptypasswords(username=None, param=None):
    """
    CIS 5.1.19 - Apply PermitEmptyPasswords
    - param: dict, örn. {"PermitEmptyPasswords": "no"} veya {"PermitEmptyPasswords": "yes"}
    """
    try:
        value =  "no"

        check_ok, msg = check_sshd_permitemptypasswords()
        if check_ok and "hatalı" not in msg:
            return True, f"Zaten uygun: {msg}"

        conf_files = [SSHD_CONFIG] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        fixed_files = []
        failed_files = []

        for conf_file in conf_files:
            try:
                run_command(["sudo", "cp", conf_file, f"{conf_file}.bak"])

                run_command(["sudo", "sed", "-i", "/^\\s*PermitEmptyPasswords/d", conf_file])

                run_command(["sudo", "sed", "-i", f"1iPermitEmptyPasswords {value}", conf_file])

                fixed_files.append(conf_file)
            except Exception as e:
                failed_files.append(f"{conf_file} hata: {str(e)}")

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"SSH servisi reload edilemedi: {output}"

        check_ok2, msg2 = check_sshd_permitemptypasswords()
        if check_ok2:
            return True, f"PermitEmptyPasswords başarıyla ayarlandı: {value}. Düzeltme yapılan dosyalar: {fixed_files}"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}. Hatalı dosyalar: {failed_files}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.19][APPLY] {msg}")
        return False, f"PermitEmptyPasswords uygulama hatası: {msg}"




def check_sshd_permitrootlogin():
    """CIS 5.1.20 - Check PermitRootLogin """

    conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
    permit_ok = True
    messages = []

    for conf_file in conf_files:
        try:
            with open(conf_file) as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean.startswith("#"):
                        continue  # yorum satırlarını atla
                    if line_clean.lower().startswith("permitrootlogin"):
                        parts = line_clean.split()
                        value = parts[1].lower() if len(parts) >= 2 else ""
                        if value != "no":
                            permit_ok = False
                            messages.append(f"{conf_file}: PermitRootLogin hatalı ({value})")
                        else:
                            messages.append(f"{conf_file}: PermitRootLogin uygun ({value})")
        except Exception as e:
            permit_ok = False
            messages.append(f"{conf_file} okunamadı: {str(e)}")

    if permit_ok:
        return True, "Tüm dosyalarda PermitRootLogin uygun. " + "; ".join(messages)
    else:
        return False, "PermitRootLogin hatalı: " + "; ".join(messages)



def apply_sshd_permitrootlogin(username=None, param=None):
    """
    CIS 5.1.20 - Apply PermitRootLogin
    """
    try:
        value = "no"

        check_ok, msg = check_sshd_permitrootlogin()
        if check_ok and "hatalı" not in msg:
            return True, f"Zaten uygun: {msg}"

        conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        fixed_files = []
        failed_files = []

        for conf_file in conf_files:
            try:
                run_command(["sudo", "cp", conf_file, f"{conf_file}.bak"])

                run_command(["sudo", "sed", "-i", "/^\\s*PermitRootLogin/d", conf_file])

                run_command(["sudo", "sed", "-i", f"1iPermitRootLogin {value}", conf_file])
                fixed_files.append(conf_file)
            except Exception as e:
                failed_files.append(f"{conf_file} hata: {str(e)}")

        ok, output = run_command(["sudo", "systemctl", "reload", "sshd"])
        if not ok:
            return False, f"SSH servisi reload edilemedi: {output}"

        check_ok2, msg2 = check_sshd_permitrootlogin()
        if check_ok2:
            return True, f"PermitRootLogin başarıyla ayarlandı: {value}. Düzeltme yapılan dosyalar: {fixed_files}"
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg2}. Hatalı dosyalar: {failed_files}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.20][APPLY] {msg}")
        return False, f"PermitRootLogin uygulama hatası: {msg}"


def check_sshd_permit_user_environment():
    """
    CIS 5.1.21 - Ensure sshd PermitUserEnvironment is disabled
    
    Kontrol fonksiyonu: sshd PermitUserEnvironment ayarı "no" mu diye kontrol eder.
    
    Returns:
        (bool, str): True/False ve açıklama mesajı
    """
    try:
        
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        for line in output.stdout.splitlines():
            if line.strip().lower().startswith("permituserenvironment"):
                value = line.strip().split()[1].lower()
                if value == "no":
                    return True, "PermitUserEnvironment zaten 'no' olarak ayarlanmış."
                else:
                    return False, f"PermitUserEnvironment '{value}' olarak ayarlı, 'no' olmalı."
        return False, "PermitUserEnvironment ayarı bulunamadı, 'no' olarak ayarlanmalı."
    except Exception as e:
        return False, f"Kontrol sırasında hata oluştu: {e}"


def apply_sshd_permit_user_environment(username=None, param=None):
    """
    CIS 5.1.21 - Ensure sshd PermitUserEnvironment is disabled
    
    Düzeltme fonksiyonu: PermitUserEnvironment 'no' değilse, düzeltir.
    """
    try:
        is_ok, message = check_sshd_permit_user_environment()
        if is_ok:
            return True, message

        try:
            config_file = "/etc/ssh/sshd_config"
            backup_file = f"{config_file}.bak"

            shutil.copy2(config_file, backup_file)

            with open(config_file, "r") as f:
                lines = f.readlines()

            found = False
            with open(config_file, "w") as f:
                for line in lines:
                    if line.strip().lower().startswith("permituserenvironment"):
                        f.write("PermitUserEnvironment no\n")
                        found = True
                    else:
                        f.write(line)
                if not found:
                    f.write("\nPermitUserEnvironment no\n")

            success, output = run_command(["systemctl", "restart", "sshd"])
            if not success:
                return False, f"sshd -T çalıştırılamadı: {output}"

            return True, "PermitUserEnvironment 'no' olarak ayarlandı ve sshd yeniden başlatıldı."
        except Exception as e:
            return False, f"Düzeltme sırasında hata oluştu: {e}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.21][APPLY] {msg}")
        return False, f"Uygulama sırasında hata: {msg}"



def check_sshd_usepam():
    """
    CIS 5.1.22: Ensure sshd UsePAM is enabled.
    """
    try:
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        for line in output.splitlines():
            line_clean = line.strip()
            if line_clean.startswith("#"):
                continue
            if line_clean.lower().startswith("usepam"):
                parts = line_clean.split()
                value = parts[1].lower() if len(parts) >= 2 else ""
                if value == "yes":
                    return True, "UsePAM doğru şekilde etkin: yes"
                else:
                    return False, f"UsePAM yanlış ayarlanmış: {value}"

        return False, "UsePAM ayarı bulunamadı."

    except Exception as e:
        return False, f"Kontrol hatası: {str(e)}"


def apply_sshd_usepam(username=None, param=None):
    """
    CIS 5.1.22: UsePAM ayarını uygula.
    """
    try:
        desired_value = "yes"

        if not desired_value:
            return check_sshd_usepam()

        sshd_config = "/etc/ssh/sshd_config"

        if not os.path.exists(sshd_config):
            return False, f"{sshd_config} bulunamadı."

        with open(sshd_config, "r") as f:
            lines = f.readlines()

        new_lines = [line for line in lines if not line.strip().lower().startswith("usepam")]

        new_lines.append(f"UsePAM {desired_value}\n")

        with open(sshd_config, "w") as f:
            f.writelines(new_lines)

        success, output = run_command(["systemctl", "reload", "sshd"])
        if not success:
            return False, f"sshd reload çalıştırılamadı: {output}"

        return check_sshd_usepam()

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.22][APPLY] {msg}")
        return False, f"UsePAM ayarı uygulanırken hata: {msg}"



##########    CIS HARICI POLITIKALAR   ##########


def check_ssh_key_authentication(expected_enabled=True):
    """
    Ensure SSH key-based authentication is enforced (PasswordAuthentication no)
    """
    path = "/etc/ssh/sshd_config.d/disable_password_auth.conf"
    # expected_enabled=True ise Parolalı giriş KAPALI olmalı -> no
    expected_value = "no" if expected_enabled else "yes"

    logger.info(f"[SSH Key Auth][CHECK] Kontrol ediliyor: {path}")

    if not os.path.exists(path):
        msg = f"Yapılandırma dosyası ({path}) bulunamadı."
        logger.warning(f"[SSH Key Auth][CHECK] {msg}")
        return False, msg

    try:
        with open(path, "r") as f:
            for line in f:
                line_stripped = line.strip().lower()
                if line_stripped.startswith("passwordauthentication"):
                    # Satırın başında # varsa yorum satırıdır, atlanmalı.
                    if line_stripped.startswith("#"):
                        continue
                        
                    parts = line.split()
                    if len(parts) > 1:
                        current_value = parts[1].lower()
                        
                        if current_value == expected_value:
                            msg = f"PasswordAuthentication zaten '{expected_value}' olarak ayarlı."
                            logger.info(f"[SSH Key Auth][CHECK] {msg}")
                            return True, msg
                        else:
                            msg = f"PasswordAuthentication '{current_value}', beklenen: '{expected_value}'."
                            logger.error(f"[SSH Key Auth][CHECK] HATA: {msg}")
                            return False, msg

            msg = "PasswordAuthentication satırı override dosyasında bulunamadı."
            logger.warning(f"[SSH Key Auth][CHECK] {msg}")
            return False, msg

    except PermissionError:
        msg = f"Yetki hatası: {path} dosyası okunamıyor. Root yetkisi gerekli."
        logger.error(f"[SSH Key Auth][CHECK] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Kontrol sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[SSH Key Auth][CHECK] {msg}")
        return False, msg


def apply_ssh_key_authentication(username=None, param=None):
    """
    CIS 5.x.x - SSH'de sadece anahtar temelli kimlik doğrulamayı zorunlu hale getirir.
    :param enable: True ise parolalı giriş devre dışı bırakılır (default: True).
    """
    param = param or {}
    enable = param.get("enable", True)  # True ise parola kapatılır
    if enable:
        logger.info("[SSH Key Auth][APPLY] Anahtar tabanlı kimlik doğrulamayı zorunlu kılma başlatıldı.")
    else:
        logger.info("[SSH Key Auth][APPLY] Parolalı kimlik doğrulamayı etkinleştirme başlatıldı.")

    success, message = check_ssh_key_authentication(enable)
    if success:
        return True, f"Değişiklik gerekmedi: {message}"

    filename = "disable_password_auth.conf"
    dir_path = "/etc/ssh/sshd_config.d"
    full_path = os.path.join(dir_path, filename)
    setting = "no" if enable else "yes"  # True ise parola kapatılır

    try:
        # 1. Dizini oluştur (Zaten varsa geçer)
        os.makedirs(dir_path, exist_ok=True)
        logger.debug(f"[SSH Key Auth][APPLY] Dizin oluşturuldu/kontrol edildi: {dir_path}")

        # 2. Yapılandırma dosyasını yaz
        with open(full_path, "w") as f:
            f.write(f"PasswordAuthentication {setting}\n")
            
        logger.info(f"[SSH Key Auth][APPLY] '{full_path}' dosyasına 'PasswordAuthentication {setting}' yazıldı.")

        # 3. SSHD servisini yeniden yükle (run_command gereklidir)
        logger.info("[SSH Key Auth][APPLY] sshd servisi yeniden yükleniyor...")
        success_reload, output_reload = run_command(["systemctl", "reload", "sshd"])
        
        if not success_reload:
            # Yeniden yükleme başarısız olursa, yeniden başlatmayı dene
            logger.warning(f"[SSH Key Auth][APPLY] Yeniden yükleme başarısız: {output_reload}. Yeniden başlatma deneniyor...")
            success_reload, output_reload = run_command(["systemctl", "restart", "sshd"])
            
            if not success_reload:
                msg = f"sshd servisi yeniden yüklenemedi/başlatılamadı: {output_reload}"
                logger.error(f"[SSH Key Auth][APPLY] HATA: {msg}")
                return False, msg


        status_message = "devre dışı bırakıldı (zorunlu kılındı)" if enable else "etkinleştirildi"
        return True, f"SSH parolalı kimlik doğrulama başarıyla {status_message} ve sshd servisi güncellendi."

    except PermissionError:
        msg = "Yetki hatası: Dosya yazma veya servis kontrolü için Root yetkisi gerekli."
        logger.error(f"[SSH Key Auth][APPLY] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Uygulama sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[SSH Key Auth][APPLY] HATA: {msg}")
        return False, msg



def check_ssh_port_change(desired_port):
    """
    [CHECK] SSH portu istenilen porta ayarlanmış mı kontrol eder.
    """
    conf_file = "/etc/ssh/sshd_config.d/ssh_port.conf"
    if not os.path.exists(conf_file):
        logger.warning("[CHECK][SSH PORT] %s dosyası bulunamadı.", conf_file)
        return False, "Konfigürasyon dosyası yok."

    try:
        with open(conf_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            if line.strip().startswith("Port") and str(desired_port) in line:
                logger.info("[CHECK][SSH PORT] SSH portu doğru ayarlanmış: %s", desired_port)
                return True, f"SSH portu {desired_port} olarak ayarlanmış."
        logger.warning("[CHECK][SSH PORT] SSH portu %s olarak ayarlanmamış.", desired_port)
        return False, f"SSH portu {desired_port} olarak ayarlanmamış."
    except Exception as e:
        logger.error(f"[CHECK][SSH PORT] Hata: {e}")
        return False, str(e)


def apply_ssh_port_change(username=None, param=None):
    """
    [APPLY] SSH portunu değiştirir (/etc/ssh/sshd_config.d/ssh_port.conf üzerinden).
    Param: {"Port": "2222"}
    """
    try:
        if not param:
            logger.error("[APPLY][SSH PORT] Parametre eksik.")
            return False, "Parametre eksik."

        if isinstance(param, str):
            try:
                param_data = json.loads(param)
            except json.JSONDecodeError:
                logger.error("[APPLY][SSH PORT] Parametre geçerli bir JSON formatında değil.")
                return False, "Parametre geçerli bir JSON formatında değil."
        elif isinstance(param, dict):
            param_data = param
        else:
            logger.error("[APPLY][SSH PORT] Parametre türü geçersiz: %s", type(param))
            return False, "Parametre türü geçersiz."

        if "Port" not in param_data:
            logger.error("[APPLY][SSH PORT] JSON içinde 'Port' anahtarı bulunamadı.")
            return False, "JSON içinde 'Port' anahtarı bulunamadı."

        port = str(param_data.get("Port"))
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            logger.error("[APPLY][SSH PORT] Geçersiz port numarası: %s", port)
            return False, "Geçersiz port numarası. 1-65535 aralığında bir sayı girin."
        if port == "22":
            logger.error("[APPLY][SSH PORT] Port numarası 22 olamaz.")
            return False, "Port numarası 22 olarak ayarlanamaz. Lütfen farklı bir port girin."

        check_result, msg = check_ssh_port_change(port)
        if check_result:
            logger.info("[APPLY][SSH PORT] SSH zaten bu portta çalışıyor: %s", port)
            return False, f"SSH zaten bu port üzerinden çalışıyor: {port}"

        conf_dir = "/etc/ssh/sshd_config.d"
        conf_file = os.path.join(conf_dir, "ssh_port.conf")
        os.makedirs(conf_dir, exist_ok=True)

        if os.path.exists(conf_file):
            os.remove(conf_file)

        with open(conf_file, "w") as f:
            f.write(f"Port {port}\n")

        logger.info("[APPLY][SSH PORT] %s dosyası oluşturuldu, Port=%s", conf_file, port)

        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            logger.info("[APPLY][SSH PORT] SSH portu %s olarak başarıyla ayarlandı.", port)
            return True, f"SSH portu {port} olarak başarıyla ayarlandı."
        else:
            logger.error("[APPLY][SSH PORT] SSH servisi yeniden başlatılamadı: %s", output)
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        logger.error(f"[APPLY][SSH PORT] Hata: {e}")
        return False, f"SSH port değiştirme hatası: {str(e)}"


def check_restrict_ssh_to_ips(allowed_ips):
    """
    [CHECK][SSH RESTRICT] restrict_ssh_to_ips politikası uygulanmış mı kontrol eder.
    """
    sshd_conf_path = "/etc/ssh/sshd_config.d/restrict_ips.conf"
    if not os.path.exists(sshd_conf_path):
        return False

    try:
        with open(sshd_conf_path, "r") as f:
            content = f.read()

        # Tüm IP'lerin config dosyasında olup olmadığını kontrol et
        for ip in allowed_ips:
            if f"Match Address {ip}" not in content:
                return False

        logger.info("[CHECK][SSH RESTRICT] Politika uygulanmış görünüyor. IP listesi: %s", ", ".join(allowed_ips))
        return True

    except Exception as e:
        logger.error("[CHECK][SSH RESTRICT] Kontrol sırasında hata: %s", e)
        return False
        

def apply_restrict_ssh_to_ips(username=None, param=None):
    """
    [APPLY][SSH RESTRICT] Yalnızca belirli IP adreslerinden SSH erişimine izin verir.
    """
    try:
        if not param:
            logger.error("[APPLY][SSH RESTRICT] Parametre eksik.")
            return False, "Parametre eksik."

        if isinstance(param, str):
            param = json.loads(param)

        allowed_ips = param.get("ip_addresses")
        if not allowed_ips or not isinstance(allowed_ips, list):
            logger.error("[APPLY][SSH RESTRICT] Geçerli bir IP listesi girilmedi.")
            return False, "Geçerli bir IP listesi girilmedi."

        if check_restrict_ssh_to_ips(allowed_ips):
            logger.warning("[APPLY][SSH RESTRICT] Bu SSH erişim politikası zaten uygulanmış.")
            return False, "Bu SSH erişim politikası zaten uygulanmış."

        # SSH config'e eklenecek Match kısmı
        match_block = "\n# Olmayan Kullanici ile herkesi engelle\n"
        match_block += "AllowUsers yokkullanici\n"

        match_block += "\n\n# Politikayla eklenen IP sınırı\n"
        for ip in allowed_ips:
            match_block += f"Match Address {ip}\n    AllowUsers {os.getlogin()}\n"

        sshd_conf_path = "/etc/ssh/sshd_config.d/restrict_ips.conf"
        with open(sshd_conf_path, "w") as f:
            f.write(match_block)

        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            logger.info("[APPLY][SSH RESTRICT] SSH erişimi şu IP’lerle sınırlandırıldı: %s", ", ".join(allowed_ips))
            return True, f"Yalnızca şu IP'lerden SSH erişimine izin verildi: {', '.join(allowed_ips)}"
        else:
            logger.error("[APPLY][SSH RESTRICT] SSH servisi yeniden başlatılamadı: %s", output)
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        logger.error("[APPLY][SSH RESTRICT] Hata: %s", e)
        return False, f"Politika hatası: {str(e)}"


