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
    for f in glob.glob("/etc/ssh/**/*", recursive=True):
        try:
            # ssh-keygen ile gerçekten private key mi kontrol eder
            ok, _ = run_command(["ssh-keygen", "-lf", f])
            if ok:
                # dosya tipini kontrol eder
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

        matches = re.findall(
            r'^(allowusers|allowgroups|denyusers|denygroups)\s+.+$',
            output, re.MULTILINE
        )

        if not matches:
            # config dosyaları kontrolü
            for path in get_all_sshd_config_files():
                with open(path, "r") as f:
                    text = f.read()
                    if re.search(r'^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+', text, re.MULTILINE):
                        return True, f"Ayar {path} içinde tanımlı."

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

        sshd_files = get_all_sshd_config_files()
        if not sshd_files:
            return False, "Hiçbir SSH konfigürasyon dosyası bulunamadı."

        main_file = sshd_files[0]

        with open(main_file, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            if not any(line.strip().lower().startswith(k.lower()) for k in keys):
                new_lines.append(line)

        for key, value in non_empty.items():
            new_lines.append(f"{key} {value}\n")

        with open(main_file, "w") as f:
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
    CIS 5.1.5 - SSHD Banner kontrolü (Banner dosyası, içerik ve uygunsuz token denetimi)
    """
    try:
        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        # Banner parametresini bulur
        banner_line = [line for line in output.splitlines() if line.strip().lower().startswith("banner ")]
        if not banner_line:
            return False, "Banner ayarı bulunamadı."

        _, path = banner_line[0].split(maxsplit=1)
        if not os.path.exists(path):
            return False, f"Banner dosyası mevcut değil: {path}"

        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return False, "Banner dosyası boş."

        # Uygunsuz karakter dizilerini kontrol eder
        forbidden_tokens = ["\\m", "\\r", "\\s", "\\v"]
        for token in forbidden_tokens:
            if token in content:
                return False, f"Banner dosyası uygunsuz içerik içeriyor: {token}"

        # OS kimliği (örnek: "debian", "ubuntu", "pardus") bulunmamalı
        os_id = None
        try:
            with open("/etc/os-release", "r") as osr:
                for line in osr:
                    if line.startswith("ID="):
                        os_id = line.split("=", 1)[1].replace('"', '').strip().lower()
                        break
        except Exception:
            pass

        if os_id and re.search(rf"\b{re.escape(os_id)}\b", content, re.IGNORECASE):
            return False, f"Banner dosyası işletim sistemi kimliği içeriyor: {os_id}"

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
        message = param.get("BannerMessage", "").strip() if param else ""
        if not message:
            return False, "Banner mesajı parametre olarak verilmedi."

        with open(BANNER_FILE, "w", encoding="utf-8") as f:
            f.write(message + "\n")

        sshd_files = get_all_sshd_config_files()
        if not sshd_files:
            return False, "SSH yapılandırma dosyası bulunamadı."

        main_file = sshd_files[0]  # /etc/ssh/sshd_config

        # Banner satırını düzenle (ilk Include/Match'ten önce olacak şekilde)
        with open(main_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        banner_inserted = False
        for line in lines:
            stripped = line.strip().lower()
            if not banner_inserted and (stripped.startswith("include") or stripped.startswith("match")):
                new_lines.append(f"Banner {BANNER_FILE}\n")
                banner_inserted = True
            if stripped.startswith("banner "):
                # varsa eski satırı değiştir
                if not banner_inserted:
                    new_lines.append(f"Banner {BANNER_FILE}\n")
                    banner_inserted = True
            else:
                new_lines.append(line)

        if not banner_inserted:
            new_lines.insert(0, f"Banner {BANNER_FILE}\n")

        with open(main_file, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        success, output = run_command(["systemctl", "reload", "sshd"])
        if not success:
            return False, f"sshd reload başarısız: {output}"

        return check_sshd_banner()

    except Exception as ex:
        msg = f"Hata: {str(ex)}"
        logger.error(f"[CIS 5.1.5][APPLY] {msg}")
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
        for line in output.splitlines():
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
    (Tüm sshd_config ve Include dosyalarında uygular)
    """
    try:
        new_ciphers = param.get("ciphers") if param else DEFAULT_CIPHERS
        config_files = get_all_sshd_config_files()

        if not config_files:
            return False, "Hiç sshd config dosyası bulunamadı."

        applied = False

        for conf_file in config_files:
            backup_file = f"{conf_file}.bak"
            shutil.copy2(conf_file, backup_file)

            with open(conf_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            updated_lines = []
            ciphers_set = False

            for line in lines:
                if line.strip().lower().startswith("ciphers "):
                    updated_lines.append(f"Ciphers {new_ciphers}\n")
                    ciphers_set = True
                else:
                    updated_lines.append(line)

            # Eğer hiçbir yerde yoksa en sona ekler
            if not ciphers_set:
                updated_lines.append(f"\n# SSH Ciphers configuration per CIS 5.1.6\n")
                updated_lines.append(f"Ciphers {new_ciphers}\n")

            with open(conf_file, "w", encoding="utf-8") as f:
                f.writelines(updated_lines)

            applied = True

        if not applied:
            return False, "Hiçbir sshd_config dosyasına yazılamadı."

        # Config syntax kontrolü
        success, output = run_command(["sshd", "-t"])
        if not success:
            # Hatalıysa geri alır
            for conf_file in config_files:
                shutil.copy2(f"{conf_file}.bak", conf_file)
            return False, f"Config test hatası: {output}"

        success, output = run_command(["systemctl", "restart", "sshd"])
        if not success:
            return False, f"sshd restart başarısız: {output}"

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
    CIS 5.1.7 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
    """
    try:
        desired_interval = param.get("ClientAliveInterval")
        desired_count = param.get("ClientAliveCountMax")

        all_configs = ""
        for cfg_file in get_all_sshd_config_files():
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    all_configs += f.read() + "\n"
            except Exception:
                continue

        success, output = run_command(["sshd", "-T"])
        if not success:
            return False, f"sshd -T çalıştırılamadı: {output}"

        current = {}
        for line in output.splitlines():
            key_val = line.strip().split(maxsplit=1)
            if len(key_val) != 2:
                continue
            key, val = key_val
            if key == "clientaliveinterval":
                current["ClientAliveInterval"] = int(val)
            elif key == "clientalivecountmax":
                current["ClientAliveCountMax"] = int(val)

        if current.get("ClientAliveInterval", 0) <= 0:
            return False, f"ClientAliveInterval {current.get('ClientAliveInterval')} (0 veya daha az olmamalı)"
        if current.get("ClientAliveCountMax", 0) <= 0:
            return False, f"ClientAliveCountMax {current.get('ClientAliveCountMax')} (0 olmamalı)"

        if desired_interval is not None:
            if int(current.get("ClientAliveInterval", -1)) != int(desired_interval):
                return False, f"ClientAliveInterval beklenen {desired_interval}, mevcut {current.get('ClientAliveInterval')}"
        if desired_count is not None:
            if int(current.get("ClientAliveCountMax", -1)) != int(desired_count):
                return False, f"ClientAliveCountMax beklenen {desired_count}, mevcut {current.get('ClientAliveCountMax')}"

        return True, "ClientAliveInterval ve ClientAliveCountMax doğru yapılandırılmış."

    except Exception as ex:
        return False, f"Hata: {str(ex)}"


def apply_ssh_client_alive(username=None, param=None):
    """
    CIS 5.1.7 düzeltme: - Apply ClientAliveInterval and ClientAliveCountMax
    Gereksinim:
        ClientAliveInterval 1–300 arasında olmalı (önerilen: 15–60)
        ClientAliveCountMax 3 veya daha az olmalı
    İşlev:
        - Gelen parametreleri uygular (ör: {"ClientAliveInterval": 60, "ClientAliveCountMax": 3})
    """

    try:
        if not param or not all(k in param for k in ["ClientAliveInterval", "ClientAliveCountMax"]):
            return False, "Eksik parametre: 'ClientAliveInterval' ve 'ClientAliveCountMax' belirtilmeli."

        interval = int(param.get("ClientAliveInterval", 60))
        count = int(param.get("ClientAliveCountMax", 3))

        if not (1 <= interval <= 300):
            return False, f"ClientAliveInterval geçersiz: {interval}. 1-300 aralığında olmalı."
        if count > 3:
            return False, f"ClientAliveCountMax çok yüksek: {count}. CIS en fazla 3 önerir."

        ok, msg = check_ssh_client_alive(param)
        if ok and "uygun" in msg.lower():
            return True, f"Zaten uygun: {msg} (Parametreler: {param})"

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern_interval = re.compile(r'^\s*#?\s*ClientAliveInterval\b', re.IGNORECASE)
        pattern_count = re.compile(r'^\s*#?\s*ClientAliveCountMax\b', re.IGNORECASE)

        updated = False
        for i, line in enumerate(lines):
            if pattern_interval.match(line):
                lines[i] = f"ClientAliveInterval {interval}\n"
                updated = True
            elif pattern_count.match(line):
                lines[i] = f"ClientAliveCountMax {count}\n"
                updated = True

        if not any(pattern_interval.match(l) for l in lines):
            lines.insert(insert_index, f"ClientAliveInterval {interval}\n")
            insert_index += 1
        if not any(pattern_count.match(l) for l in lines):
            lines.insert(insert_index, f"ClientAliveCountMax {count}\n")

        backup = f"{SSHD_CONFIG}.bak"
        if not os.path.exists(backup):
            run_command(["cp", SSHD_CONFIG, backup])

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup, SSHD_CONFIG])
            return False, f"sshd -t doğrulaması başarısız: {out_test}"

        ok_reload, out_reload = run_command(["systemctl", "reload", "sshd"])
        if not ok_reload:
            return False, f"SSH servisi reload başarısız: {out_reload}"

        ok_final, msg_final = check_ssh_client_alive(param)
        if ok_final:
            return True, (
                f"ClientAliveInterval={interval}, ClientAliveCountMax={count} başarıyla uygulandı. "
                f"({msg_final})"
            )
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as ex:
        msg = f"Hata: {str(ex)}"
        logger.error(f"[CIS 5.1.7][APPLY] {msg}")
        return False, f"SSH ClientAlive ayar hatası: {msg}"



def check_sshd_disableforwarding():
    """
    CIS 5.1.8 - Ensure sshd DisableForwarding is enabled.
    Beklenen: DisableForwarding yes
    """
    try:
        ok, output = run_command(["sshd", "-T"])
        if not ok:
            return False, f"sshd -T çalıştırılamadı: {output}"

        for line in output.splitlines():
            if line.lower().startswith("disableforwarding"):
                value = line.split()[1].lower()
                if value == "yes":
                    return True, "DisableForwarding doğru yapılandırılmış (yes)."
                else:
                    return False, f"DisableForwarding değeri yanlış: {value}"

        return False, "DisableForwarding parametresi bulunamadı (varsayılan: no olabilir)."

    except Exception as e:
        return False, f"Hata (check_sshd_disableforwarding): {e}"


def apply_sshd_disableforwarding(username=None, param=None):
    """
    CIS 5.1.8 - DisableForwarding 'yes' olarak ayarlanır.
    Include ve Match öncesine ekler, yorumlu satırları aktif hale getirir.
    """
    try:
        ok, msg = check_sshd_disableforwarding()
        if ok:
            return True, f"Her şey zaten doğru: {msg}"

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^\s*#?\s*DisableForwarding\b', re.IGNORECASE)
        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        found = False
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = "DisableForwarding yes\n"
                found = True
                break

        if not found:
            lines.insert(insert_index, "DisableForwarding yes\n")

        # Değişiklikleri kaydeder
        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok, out = run_command(["sshd", "-t"])
        if not ok:
            return False, f"sshd yapılandırma testi başarısız: {out}"

        ok, out = run_command(["systemctl", "reload", "sshd"])
        if not ok:
            return False, f"sshd reload başarısız: {out}"

        ok_final, msg_final = check_sshd_disableforwarding()
        if ok_final:
            return True, "DisableForwarding başarıyla 'yes' olarak ayarlandı."
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.8][APPLY] {msg}")
        return False, f"DisableForwarding düzenlenemedi: {msg}"



def check_sshd_gssapiauthentication():
    """
    CIS 5.1.9 - GSSAPIAuthentication kontrolü
    Hem global ayarı hem de Match bloklarının override edip etmediğini denetler.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    global_val = None
    for line in output.splitlines():
        if line.strip().startswith("gssapiauthentication"):
            global_val = line.strip().split()[-1].lower()
            break

    if global_val != "no":
        return False, f"GSSAPIAuthentication globalde hatalı: {global_val or 'tanımsız'}"

    match_found = False
    for cfg in get_all_sshd_config_files():
        try:
            with open(cfg, "r") as f:
                for line in f:
                    if line.strip().lower().startswith("match "):
                        match_found = True
                        break
        except Exception:
            continue

    if match_found:
        test_users = ["root", "testuser", "admin", "pardus", "ubuntu", "debian", "guest", "user", "sshuser", "backup"]    # burası şimdilik sabit. ip, grup vs eklenebilir
        for user in test_users:
            ok, match_out = run_command(["sshd", "-T", "-C", f"user={user}"])
            if not ok:
                continue
            for line in match_out.splitlines():
                if line.strip().startswith("gssapiauthentication"):
                    val = line.strip().split()[-1].lower()
                    if val != "no":
                        return False, f"Match bloğu kullanıcı '{user}' için GSSAPIAuthentication={val}"

    return True, "Tüm kullanıcı ve match blokları için GSSAPIAuthentication 'no' olarak ayarlanmış."



def apply_sshd_gssapiauthentication(username=None, param=None):
    """
    CIS 5.1.9 - Uygulama fonksiyonu
    SSHD yapılandırmasında GSSAPIAuthentication 'no' olarak ayarlanır.
    """
    ok, msg = check_sshd_gssapiauthentication()
    if ok:
        return True, msg

    try:
        config_files = get_all_sshd_config_files()
        if not config_files:
            return False, "Herhangi bir sshd config dosyası bulunamadı."

        updated = False

        for cfg in config_files:
            if not os.path.exists(cfg):
                continue

            with open(cfg, "r") as f:
                lines = f.readlines()

            new_lines = []
            found = False
            inserted = False

            for line in lines:
                # Var olan satırı değiştirir
                if line.strip().lower().startswith("gssapiauthentication"):
                    new_lines.append("GSSAPIAuthentication no\n")
                    found = True
                    continue

                # Eğer Include veya Match satırından önce ekleme yapılmamışsa
                if not found and not inserted and line.strip().lower().startswith(("include", "match")):
                    new_lines.append("GSSAPIAuthentication no\n")
                    inserted = True

                new_lines.append(line)

            # Hiç bulunmadı ve eklenmediyse en sona ekler
            if not found and not inserted:
                new_lines.append("GSSAPIAuthentication no\n")

            with open(cfg, "w") as f:
                f.writelines(new_lines)

            updated = True

        if not updated:
            return False, "Herhangi bir yapılandırma dosyası düzenlenemedi."

        ok, test_output = run_command(["sshd", "-t"])
        if not ok:
            return False, f"Config test başarısız: {test_output}"

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



def check_sshd_hostbasedauthentication(test_user: str = None):
    """
    CIS 5.1.10 - Ensure HostbasedAuthentication is disabled.
    - Kontrol hem genel hem de Match blokları için yapılır.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def extract_value(out):
        for line in out.splitlines():
            if line.strip().lower().startswith("hostbasedauthentication"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[-1].lower()
        return None

    value_global = extract_value(output)
    if value_global != "no":
        return False, f"HostbasedAuthentication yanlış: {value_global or 'bulunamadı'}"

    if test_user:
        ok_c, out_c = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok_c:
            value_match = extract_value(out_c)
            if value_match != "no":
                return False, f"Match bloğunda HostbasedAuthentication override edilmiş: {value_match}"
        else:
            return False, f"sshd -T -C user={test_user} çalıştırılamadı: {out_c}"

    return True, "HostbasedAuthentication doğru: no (Match blokları dahil)"

def apply_sshd_hostbasedauthentication(username=None, param=None):
    """
    CIS 5.1.10 - Ensure HostbasedAuthentication is disabled.
    - Include ve Match öncesine 'HostbasedAuthentication no' ekler.
    - get_all_sshd_config_files() kullanır.
    """
    all_files = get_all_sshd_config_files()
    if not all_files:
        all_files = ["/etc/ssh/sshd_config"]

    main_cfg = all_files[0]
    ok, msg = check_sshd_hostbasedauthentication()
    if ok:
        return True, msg

    try:
        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = None
        for idx, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = idx
                break
        if insert_index is None:
            insert_index = 0

        pattern = re.compile(r'^\s*HostbasedAuthentication\b', re.IGNORECASE)
        hba_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        if hba_index is None:
            lines.insert(insert_index, "HostbasedAuthentication no\n")
        else:
            lines[hba_index] = re.sub(
                r'^\s*HostbasedAuthentication\s+\S+',
                "HostbasedAuthentication no",
                lines[hba_index],
                flags=re.IGNORECASE
            )

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            return False, f"sshd -t başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_hostbasedauthentication()
        if ok_final:
            return True, "HostbasedAuthentication başarıyla 'no' yapıldı."
        else:
            return False, f"Değişiklik yapıldı ama doğrulama başarısız: {msg_final}"

    except Exception as e:
        return False, f"Hata: {e}"




def check_sshd_ignorerhosts(test_user: str = None):
    """
    CIS 5.1.11 - Ensure IgnoreRhosts is enabled.
    - Kontrol hem genel hem de Match blokları için yapılır.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def extract_value(out):
        for line in out.splitlines():
            if line.strip().lower().startswith("ignorerhosts"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[-1].lower()
        return None

    value_global = extract_value(output)
    if value_global != "yes":
        return False, f"IgnoreRhosts yanlış: {value_global or 'bulunamadı'}"

    if test_user:
        ok_c, out_c = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok_c:
            value_match = extract_value(out_c)
            if value_match != "yes":
                return False, f"Match bloğunda IgnoreRhosts override edilmiş: {value_match}"
        else:
            return False, f"sshd -T -C user={test_user} çalıştırılamadı: {out_c}"

    return True, "IgnoreRhosts doğru: yes (Match blokları dahil)"


def apply_sshd_ignorerhosts(username=None, param=None):
    """
    CIS 5.1.11 - Ensure IgnoreRhosts is enabled.
    - /etc/ssh/sshd_config ve Include dosyaları üzerinde çalışır.
    - 'IgnoreRhosts yes' satırını yorumlardan temizleyip uygun yere ekler.
    """
    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = ["/etc/ssh/sshd_config"]

        main_cfg = all_files[0]

        # Önce gerçekten aktif satır var mı kontrol eder
        grep_cmd = ["grep", "-iR", "^[[:space:]]*IgnoreRhosts", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"]
        grep_ok, grep_out = run_command(grep_cmd)
        has_active = any(
            line.strip().lower().startswith("ignorerhosts yes")
            for line in grep_out.splitlines()
            if not line.strip().startswith("#")
        )

        if not has_active:
            with open(main_cfg, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # İlk Include veya Match'ten önce eklenecek
            insert_index = None
            for idx, line in enumerate(lines):
                if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                    insert_index = idx
                    break
            if insert_index is None:
                insert_index = 0

            # IgnoreRhosts satırı varsa (yorumlu olsa bile) bul
            pattern = re.compile(r'^\s*#?\s*IgnoreRhosts\b', re.IGNORECASE)
            existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

            if existing_index is None:
                lines.insert(insert_index, "IgnoreRhosts yes\n")
            else:
                lines[existing_index] = "IgnoreRhosts yes\n"

            run_command(["cp", main_cfg, f"{main_cfg}.bak"])

            with open(main_cfg, "w", encoding="utf-8") as f:
                f.writelines(lines)

            ok_test, out_test = run_command(["sshd", "-t"])
            if not ok_test:
                run_command(["mv", f"{main_cfg}.bak", main_cfg])
                return False, f"sshd -t doğrulaması başarısız: {out_test}"

            run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_ignorerhosts()
        if ok_final:
            return True, "IgnoreRhosts başarıyla 'yes' olarak ayarlandı veya zaten aktifti."
        else:
            return False, f"Değişiklik uygulandı ama doğrulama başarısız: {msg_final}"

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

        ok, out = run_command(["sshd", "-t"])
        if not ok:
            return False, f"sshd config test başarısız: {out}"

        return check_sshd_kexalgorithms()

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.12][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_sshd_logingracetime():
    """
    CIS 5.1.13 - Ensure sshd LoginGraceTime is configured (Automated)
    LoginGraceTime değerinin 1-60 saniye arası olduğunu doğrular.
    """
    all_files = get_all_sshd_config_files()
    valid = True
    messages = []

    for conf_file in all_files:
        try:
            with open(conf_file) as f:
                for line in f:
                    if re.match(r"^\s*LoginGraceTime", line, re.IGNORECASE):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                value = int(parts[1])
                                if 1 <= value <= 60:
                                    messages.append(f"{conf_file}: {value}")
                                else:
                                    valid = False
                                    messages.append(f"{conf_file}: Hatalı ({value})")
                            except ValueError:
                                valid = False
                                messages.append(f"{conf_file}: Sayısal olmayan değer ({line.strip()})")
                        else:
                            valid = False
                            messages.append(f"{conf_file}: Eksik değer ({line.strip()})")
                        break
        except Exception as e:
            valid = False
            messages.append(f"{conf_file} okunamadı: {str(e)}")

    ok, output = run_command(["sshd", "-T"])
    if not ok:
        valid = False
        messages.append(f"sshd -T çalıştırılamadı: {output}")
    else:
        match = re.search(r"logingracetime\s+(\d+)", output)
        if match:
            runtime_val = int(match.group(1))
            if not (1 <= runtime_val <= 60):
                valid = False
                messages.append(f"Runtime LoginGraceTime hatalı ({runtime_val})")
        else:
            valid = False
            messages.append("Runtime LoginGraceTime bulunamadı")

    if valid:
        return True, "LoginGraceTime uygun: " + "; ".join(messages)
    else:
        return False, "LoginGraceTime hatalı: " + "; ".join(messages)


def apply_sshd_logingracetime(username=None, param=None):
    """
    CIS 5.1.13 - Apply LoginGraceTime
    LoginGraceTime değerini 60 saniye (veya parametreye göre) olarak ayarlar.
    """
    try:
        param = param or {}
        value = int(param.get("LoginGraceTime", 60))

        check_ok, msg = check_sshd_logingracetime()
        if check_ok:
            return True, f"Zaten uygun: {msg}"


        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = [line for line in lines if not re.match(r"^\s*LoginGraceTime", line, re.IGNORECASE)]

        inserted = False
        for i, line in enumerate(new_lines):
            if re.match(r"^\s*(Include|Match)", line, re.IGNORECASE):
                new_lines.insert(i, f"LoginGraceTime {value}\n")
                inserted = True
                break
        if not inserted:
            new_lines.append(f"LoginGraceTime {value}\n")

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        ok, output = run_command(["sshd", "-t"])
        if not ok:
            return False, f"sshd config test başarısız: {output}"

        ok, output = run_command(["systemctl", "reload", "sshd"])
        if not ok:
            return False, f"SSH servisi reload edilemedi: {output}"

        check_ok2, msg2 = check_sshd_logingracetime()
        if check_ok2:
            return True, f"LoginGraceTime başarıyla ayarlandı: {value}. {msg2}"
        else:
            return False, f"Uygulama sonrası doğrulama başarısız: {msg2}"

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

        loglevel = None
        for line in output.splitlines():
            if line.strip().startswith("loglevel"):
                loglevel = line.split()[1].upper()
                break

        if loglevel not in expected_levels:
            return False, f"Global LogLevel uyumsuz: {loglevel}, beklenen: {expected_levels}"

        test_users = ["root", "sshd"]
        for user in test_users:
            ok, match_out = run_command(["sshd", "-T", "-C", f"user={user}"])
            if ok:
                for line in match_out.splitlines():
                    if line.strip().startswith("loglevel"):
                        match_level = line.split()[1].upper()
                        if match_level not in expected_levels:
                            return False, f"Match bloğu ({user}) LogLevel={match_level}, beklenen: {expected_levels}"

        for file_path in get_all_sshd_config_files():
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        if line.strip().lower().startswith("loglevel "):
                            level = line.split()[1].upper()
                            if level not in expected_levels:
                                return False, f"{file_path} içinde uyumsuz LogLevel: {level}"
            except Exception:
                continue

        return True, f"sshd LogLevel uyumlu ({loglevel})"
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
    valid_levels = ["INFO", "VERBOSE"]
    if desired_level not in valid_levels:
        return False, f"Geçersiz loglevel parametresi: {desired_level}. Sadece {valid_levels} kullanılabilir."

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_file = f"{main_cfg}.bak"
        shutil.copy2(main_cfg, backup_file)

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^\s*#?\s*LogLevel\b', re.IGNORECASE)
        found_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        if found_index is not None:
            lines[found_index] = f"LogLevel {desired_level}\n"
        else:
            insert_index = 0
            for i, line in enumerate(lines):
                if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                    insert_index = i
                    break
            lines.insert(insert_index, f"LogLevel {desired_level}\n")

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok, out = run_command(["sshd", "-t"])
        if not ok:
            shutil.copy2(backup_file, main_cfg)
            return False, f"sshd -t doğrulaması başarısız: {out}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_loglevel({"level": desired_level})
        if ok_final:
            return True, f"LogLevel başarıyla '{desired_level}' yapıldı. (Yedek: {backup_file})"
        else:
            return False, f"Doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.14][APPLY] {msg}")
        return False, msg



SECURE_MACS = [
    "hmac-sha2-512",
    "hmac-sha2-384",
    "hmac-sha2-256",
    "hmac-sha1"
]

WEAK_MACS = [
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com"
]

def check_sshd_macs(param=None):
    """
    CIS 5.1.15 - Audit: Check for weak MAC algorithms.
    CIS Benchmark gereğince sshd -T çıktısında zayıf MAC'ler bulunmamalıdır.
    """
    param = param or {}
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    current_macs = []
    for line in output.splitlines():
        if line.strip().startswith("macs"):
            current_macs = line.split()[1].split(",")
            break

    if not current_macs:
        return False, "MACs ayarı bulunamadı."

    weak_found = [m for m in WEAK_MACS if m in current_macs]
    if weak_found:
        return False, f"Zayıf MAC tespit edildi: {', '.join(weak_found)}"

    return True, f"MACs güvenli: {', '.join(current_macs)}"


def apply_sshd_macs(username=None, param=None):
    """
    CIS 5.1.15 - Ensure sshd MACs are configured (CIS literal remediation)
    - Zayıf MAC algoritmalarını '-' (exclude) biçiminde devre dışı bırakır.
    - CVE-2023-48795 yaması yoksa etm@openssh.com MAC'lerini de exclude eder.
    """
    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_file = f"{main_cfg}.bak"
        if not os.path.exists(backup_file):
            shutil.copy2(main_cfg, backup_file)

        ok, msg = check_sshd_macs()
        if ok:
            return True, f"Zaten uygun: {msg}"

        # CIS'e göre hariç tutulacak MAC listesi
        weak_list = WEAK_MACS.copy()

        # CVE-2023-48795 (Terrapin) yaması kontrolü
        ok_v, ssh_ver_out = run_command(["ssh", "-V"])
        patch_missing = True
        if ok_v:
            match = re.search(r"OpenSSH_(\d+\.\d+)", ssh_ver_out)
            if match:
                ver = float(match.group(1))
                if ver >= 9.6:
                    patch_missing = False

        if patch_missing:
            # CIS uyarısına göre etm@openssh.com MAC'lerini de devre dışı bırak
            weak_list += [
                "hmac-sha1-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512-etm@openssh.com"
            ]

        exclude_line = f"MACs -{','.join(weak_list)}\n"

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # İlk Include veya Match'ten önce ekle
        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        # Mevcut MACs satırı varsa değiştir, yoksa ekler
        pattern = re.compile(r'^\s*#?\s*MACs\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        if existing_index is not None:
            lines[existing_index] = exclude_line
        else:
            lines.insert(insert_index, exclude_line)

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            shutil.copy2(backup_file, main_cfg)
            return False, f"sshd -t doğrulaması başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_macs()
        if ok_final:
            return True, f"Zayıf MAC algoritmaları devre dışı bırakıldı. Hariç tutulanlar: {', '.join(weak_list)}"
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.15][APPLY] {msg}")
        return False, f"MACs düzenlenemedi: {msg}"




def check_sshd_maxauthtries(test_user: str = None):
    """
    CIS 5.1.16 - Check MaxAuthTries
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}", None

    def extract_value(out):
        for line in out.splitlines():
            if line.strip().lower().startswith("maxauthtries"):
                try:
                    return int(line.split()[1])
                except Exception:
                    return None
        return None

    value = extract_value(output)
    if value is None:
        return False, "MaxAuthTries parametresi bulunamadı (varsayılan 6 uygunsuz).", None

    if value > 4:
        return False, f"MaxAuthTries çok yüksek: {value}", value

    # Match blok kontrolü
    if test_user:
        ok2, out2 = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok2:
            match_val = extract_value(out2)
            if match_val and match_val > 4:
                return False, f"Match bloğunda MaxAuthTries={match_val}", match_val

    return True, f"MaxAuthTries uygun: {value}", value


def apply_sshd_maxauthtries(username=None, param=None):
    """
    CIS 5.1.16 - Apply MaxAuthTries
    param: dict, örn. {"MaxAuthTries": 3}

    - sshd -t testi başarısız olursa geri alır
    """
    desired = int(param.get("MaxAuthTries", 4)) if param else 4

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        # Eğer .bak yoksa bir defalık oluştur
        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        ok, msg, current = check_sshd_maxauthtries()
        if ok and current == desired:
            return True, f"MaxAuthTries zaten uygun: {current}"

        # Mevcut satırları okur
        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # İlk Include veya Match öncesine ekleme
        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        # #MaxAuthTries gibi yorumlu satırları da yakala
        pattern = re.compile(r'^\s*#?\s*MaxAuthTries\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        # Satır varsa değiştir, yoksa yeni ekle
        new_line = f"MaxAuthTries {desired}\n"
        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = new_line

        # Dosyayı yeniden yaz
        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t doğrulaması başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final, val_final = check_sshd_maxauthtries()
        if ok_final:
            return True, f"MaxAuthTries başarıyla {val_final} olarak ayarlandı."
        else:
            return False, f"Düzeltme yapıldı ama kontrol başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.16][APPLY] {msg}")
        return False, f"Hata: {msg}"


def check_sshd_maxsessions(test_user: str = None):
    """
    CIS 5.1.17 - Check MaxSessions.
    - MaxSessions 10 veya daha az olmalı.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def get_value(out):
        for line in out.splitlines():
            if line.lower().startswith("maxsessions"):
                try:
                    return int(line.split()[1])
                except Exception:
                    return None
        return None

    val_global = get_value(output)
    if val_global is None:
        return False, "MaxSessions ayarı bulunamadı (varsayılan 10)."
    if val_global > 10:
        return False, f"MaxSessions çok yüksek: {val_global}"

    # Match blok kontrolü
    if test_user:
        ok_c, out_c = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok_c:
            val_match = get_value(out_c)
            if val_match and val_match > 10:
                return False, f"Match bloğunda MaxSessions çok yüksek: {val_match}"

    return True, f"MaxSessions uygun: {val_global}"


def apply_sshd_maxsessions(username=None, param=None):
    """
    CIS 5.1.17 - Apply MaxSessions 10 veya daha az olacak şekilde ayarla.
    - Include veya Match öncesine ekler.
    """
    desired = int(param.get("MaxSessions", 10)) if param else 10

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        ok, msg = check_sshd_maxsessions()
        if ok:
            return True, f"Zaten uygun: {msg}"

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#?\s*MaxSessions\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        new_line = f"MaxSessions {desired}\n"
        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = new_line


        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_maxsessions()
        if ok_final:
            return True, f"MaxSessions başarıyla {desired} olarak ayarlandı."
        else:
            return False, f"Uygulama sonrası kontrol başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.17][APPLY] {msg}")
        return False, f"MaxSessions uygulama hatası: {msg}"



def check_sshd_maxstartups(test_user: str = None):
    """
    CIS 5.1.18 - Ensure MaxStartups is configured (10:30:60 or stricter)
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def parse_value(out):
        for line in out.splitlines():
            if line.lower().startswith("maxstartups"):
                try:
                    parts = line.split()[1].split(":")
                    if len(parts) == 3:
                        return tuple(map(int, parts))
                except Exception:
                    return None
        return None

    value = parse_value(output)
    if not value:
        return False, "MaxStartups ayarı yok (varsayılan 10:30:100 uygunsuz)."

    start, pct, maxc = value
    if start <= 10 and pct <= 30 and maxc <= 60:
        return True, f"MaxStartups uygun: {start}:{pct}:{maxc}"
    else:
        return False, f"MaxStartups çok gevşek: {start}:{pct}:{maxc}"



def apply_sshd_maxstartups(username=None, param=None):
    """
    CIS 5.1.18 - Apply MaxStartups 10:30:60 (or stricter)
    - Include veya Match öncesine ekler.

    """
    desired = param.get("MaxStartups", "10:30:60") if param else "10:30:60"

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        ok, msg = check_sshd_maxstartups()
        if ok:
            return True, f"Zaten uygun: {msg}"

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#?\s*MaxStartups\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        new_line = f"MaxStartups {desired}\n"
        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = new_line

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t doğrulama hatası: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_maxstartups()
        if ok_final:
            return True, f"MaxStartups başarıyla {desired} olarak ayarlandı."
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.18][APPLY] {msg}")
        return False, f"Hata: {msg}"



def check_sshd_permitemptypasswords(test_user: str = None):
    """
    CIS 5.1.19 - Ensure PermitEmptyPasswords is disabled.
    - Beklenen: PermitEmptyPasswords no
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def extract_value(out):
        for line in out.splitlines():
            if line.strip().lower().startswith("permitemptypasswords"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].lower()
        return None

    value_global = extract_value(output)
    if value_global != "no":
        return False, f"PermitEmptyPasswords yanlış: {value_global or 'bulunamadı'}"

    if test_user:
        ok_c, out_c = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok_c:
            value_match = extract_value(out_c)
            if value_match != "no":
                return False, f"Match bloğunda PermitEmptyPasswords override edilmiş: {value_match}"
        else:
            return False, f"sshd -T -C user={test_user} çalıştırılamadı: {out_c}"

    return True, "PermitEmptyPasswords doğru: no (Match blokları dahil)"


def apply_sshd_permitemptypasswords(username=None, param=None):
    """
    CIS 5.1.19 - Ensure PermitEmptyPasswords is disabled.
    - Her durumda aktif satır olarak 'PermitEmptyPasswords no' bırakır.
    """
    desired = "no"

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#*\s*PermitEmptyPasswords\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)
        new_line = f"PermitEmptyPasswords {desired}\n"

        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = re.sub(
                r'^\s*#*\s*(PermitEmptyPasswords).*',
                fr'\1 {desired}',
                lines[existing_index],
                flags=re.IGNORECASE
            ).strip() + "\n"

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t doğrulama hatası: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_permitemptypasswords()
        if ok_final:
            return True, "PermitEmptyPasswords başarıyla 'no' olarak aktif hale getirildi."
        else:
            return False, f"Değişiklik yapıldı ama doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.19][APPLY] {msg}")
        return False, f"PermitEmptyPasswords düzenlenemedi: {msg}"




def check_sshd_permitrootlogin(test_user: str = "root"):
    """
    CIS 5.1.20 - Ensure PermitRootLogin is disabled.
    - Beklenen: PermitRootLogin no
    - Match blokları dahil kontrol edilir.
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    def extract_value(out):
        for line in out.splitlines():
            if line.strip().lower().startswith("permitrootlogin"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].lower()
        return None

    value_global = extract_value(output)
    if value_global != "no":
        return False, f"PermitRootLogin yanlış: {value_global or 'bulunamadı'}"

    if test_user:
        ok_c, out_c = run_command(["sshd", "-T", "-C", f"user={test_user}"])
        if ok_c:
            value_match = extract_value(out_c)
            if value_match != "no":
                return False, f"Match bloğunda PermitRootLogin override edilmiş: {value_match}"
        else:
            return False, f"sshd -T -C user={test_user} çalıştırılamadı: {out_c}"

    return True, "PermitRootLogin doğru: no (Match blokları dahil)"


def apply_sshd_permitrootlogin(username=None, param=None):
    """
    CIS 5.1.20 - Apply PermitRootLogin
    - 'PermitRootLogin no' satırını Include veya Match öncesine ekler.
    """
    desired = "no"

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        ok, msg = check_sshd_permitrootlogin()
        if ok:
            return True, f"Zaten uygun: {msg}"

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#?\s*PermitRootLogin\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        new_line = f"PermitRootLogin {desired}\n"

        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = new_line

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_permitrootlogin()
        if ok_final:
            return True, "PermitRootLogin başarıyla 'no' olarak ayarlandı."
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.20][APPLY] {msg}")
        return False, f"PermitRootLogin düzenlenemedi: {msg}"



def check_sshd_permit_user_environment():
    """
    CIS 5.1.21 - Ensure sshd PermitUserEnvironment is disabled.
    Beklenen: PermitUserEnvironment no
    """
    ok, output = run_command(["sshd", "-T"])
    if not ok:
        return False, f"sshd -T çalıştırılamadı: {output}"

    for line in output.splitlines():
        if line.strip().lower().startswith("permituserenvironment"):
            value = line.split()[1].lower()
            if value == "no":
                return True, "PermitUserEnvironment doğru: no"
            else:
                return False, f"PermitUserEnvironment yanlış: {value}"
    return True, "PermitUserEnvironment ayarı bulunamadı (varsayılan 'no' olmalı)."


def apply_sshd_permit_user_environment(username=None, param=None):
    """
    CIS 5.1.21 - Ensure PermitUserEnvironment is disabled.
    - Her durumda aktif satır olarak 'PermitUserEnvironment no' bırakır.
    """
    desired = "no"

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#*\s*PermitUserEnvironment\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)
        new_line = f"PermitUserEnvironment {desired}\n"

        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = re.sub(
                r'^\s*#*\s*(PermitUserEnvironment).*',
                fr'\1 {desired}',
                lines[existing_index],
                flags=re.IGNORECASE
            ).strip() + "\n"

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t doğrulama başarısız: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_permit_user_environment()
        if ok_final:
            return True, "PermitUserEnvironment başarıyla 'no' olarak aktif hale getirildi."
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.21][APPLY] {msg}")
        return False, f"PermitUserEnvironment düzenlenemedi: {msg}"




def check_sshd_usepam():
    """
    CIS 5.1.22 - Ensure sshd UsePAM is enabled.
    Beklenen: UsePAM yes
    """
    try:
        ok, output = run_command(["sshd", "-T"])
        if not ok:
            return False, f"sshd -T çalıştırılamadı: {output}"

        for line in output.splitlines():
            if line.strip().lower().startswith("usepam"):
                value = line.split()[1].lower()
                if value == "yes":
                    return True, "UsePAM doğru: yes"
                else:
                    return False, f"UsePAM yanlış: {value}"
        return False, "UsePAM ayarı bulunamadı (varsayılan 'yes' olmalı)."

    except Exception as e:
        return False, f"Kontrol hatası: {str(e)}"


def apply_sshd_usepam(username=None, param=None):
    """
    CIS 5.1.22 - Apply UsePAM
    - Include veya Match öncesine 'UsePAM yes' ekler.
    - #UsePAM satırlarını aktif hale getirir.
    """
    desired = "yes"

    try:
        all_files = get_all_sshd_config_files()
        if not all_files:
            all_files = [SSHD_CONFIG]

        main_cfg = all_files[0]
        backup_path = f"{main_cfg}.bak"

        if not os.path.exists(backup_path):
            run_command(["cp", main_cfg, backup_path])

        ok, msg = check_sshd_usepam()
        if ok:
            return True, f"Zaten uygun: {msg}"

        with open(main_cfg, "r", encoding="utf-8") as f:
            lines = f.readlines()

        insert_index = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(Include|Match)\b', line, re.IGNORECASE):
                insert_index = i
                break

        pattern = re.compile(r'^\s*#?\s*UsePAM\b', re.IGNORECASE)
        existing_index = next((i for i, l in enumerate(lines) if pattern.match(l)), None)

        new_line = f"UsePAM {desired}\n"

        if existing_index is None:
            lines.insert(insert_index, new_line)
        else:
            lines[existing_index] = new_line

        with open(main_cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok_test, out_test = run_command(["sshd", "-t"])
        if not ok_test:
            run_command(["cp", backup_path, main_cfg])
            return False, f"sshd -t doğrulama hatası: {out_test}"

        run_command(["systemctl", "reload", "sshd"])

        ok_final, msg_final = check_sshd_usepam()
        if ok_final:
            return True, "UsePAM başarıyla 'yes' olarak ayarlandı."
        else:
            return False, f"Değişiklik yapıldı ancak doğrulama başarısız: {msg_final}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.22][APPLY] {msg}")
        return False, f"UsePAM düzenlenemedi: {msg}"




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

        os.makedirs(dir_path, exist_ok=True)
        logger.debug(f"[SSH Key Auth][APPLY] Dizin oluşturuldu/kontrol edildi: {dir_path}")

        with open(full_path, "w") as f:
            f.write(f"PasswordAuthentication {setting}\n")
            
        logger.info(f"[SSH Key Auth][APPLY] '{full_path}' dosyasına 'PasswordAuthentication {setting}' yazıldı.")

        logger.info("[SSH Key Auth][APPLY] sshd servisi yeniden yükleniyor...")
        success_reload, output_reload = run_command(["systemctl", "reload", "sshd"])
        
        if not success_reload:
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

        # Tüm IP'lerin config dosyasında olup olmadığını kontrol eder
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


