###############################################################################################################################
###                                                                                                                         ###
###                                             CIS SSHD GÜVENLİK REVERT                                                    ###
###                                                                                                                         ###
###############################################################################################################################

import os
import re
import stat
import shutil, glob

from logger import logger
from utils import run_command, get_username, get_groupname, get_all_sshd_config_files


from policies.ssh_configure import (
    find_ssh_private_host_keys,
    check_ssh_private_host_key_permissions,
    find_ssh_public_host_keys,
    check_ssh_public_host_key_permissions,
    check_sshd_access, check_sshd_banner,
    check_sshd_ciphers, read_sshd_config,
    write_sshd_config, reload_sshd,
    check_ssh_client_alive, check_sshd_disableforwarding,
    check_sshd_gssapiauthentication)


SSHD_CONFIG = "/etc/ssh/sshd_config"
BANNER_FILE = "/etc/issue.net"
DEFAULT_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
BACKUP_CONFIG = "/etc/ssh/sshd_config.bak"


def revert_sshd_config_permissions():
    """
    CIS 5.1.1 - SSH config dosyalarının izinlerini geri al (apply ile yapılan değişiklikleri geri çevirir)
    Not: Gerçek eski izinleri kaydetmediğimiz için revert, dosyaları güvenli varsayılan izinlere getirir.
    """
    try:
        files_to_revert = get_all_sshd_config_files()
        reverted = []
        failed = []

        for f in files_to_revert:
            try:
                # Revert mantığı: root olmayan kullanıcı ve group varsa root:root yap, izinleri 644 yap
                st = os.stat(f)
                user = get_username(st.st_uid)
                group = get_groupname(st.st_gid)
                perms = oct(st.st_mode & 0o777)

                # Eğer zaten root:root ve 600’dan kısıtlı ise revert gerekli değil
                if user == "root" and group == "root" and int(perms, 8) <= 0o600:
                    reverted.append(f"{f} zaten uyumlu, değişiklik yapılmadı.")
                    continue

                # Eski izin bilgisi yok, revert mantığı: 644 ile geri dön
                run_command(["chmod", "644", f])
                run_command(["chown", "root:root", f])

                st = os.stat(f)
                perms = oct(st.st_mode & 0o777)
                user = get_username(st.st_uid)
                group = get_groupname(st.st_gid)

                if int(perms, 8) == 0o644 and user == "root" and group == "root":
                    reverted.append(f"{f} revert edildi (mode={perms}, owner={user}, group={group})")
                else:
                    failed.append(f"{f} revert sonrası da hatalı (mode={perms}, owner={user}, group={group})")

            except Exception as e:
                failed.append(f"{f} revert hatası: {str(e)}")

        if failed:
            logger.warning("[CIS 5.1.1][REVERT] Bazı dosyalar revert edilemedi: " + "; ".join(failed))
            return False, "Bazı dosyalar revert edilemedi: " + "; ".join(failed)
        else:
            logger.info("[CIS 5.1.1][REVERT] Tüm SSH config dosyaları revert edildi: " + "; ".join(reverted))
            return True, "Tüm SSH config dosyaları revert edildi: " + "; ".join(reverted)

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.1][REVERT] {msg}")
        return False, f"SSH config revert hatası: {msg}"



def revert_ssh_private_host_key_permissions():
    """
    CIS 5.1.2 - SSH private host key dosyalarının izin ve sahiplik değişikliklerini geri alır.
    Apply fonksiyonu ile yapılan düzeltmeleri önceki güvenli varsayılanlara çeker.
    """
    try:
        key_files = find_ssh_private_host_keys()
        if not key_files:
            return True, "SSH private host key dosyası bulunamadı, revert uygulanmadı."

        reverted, failed = [], []

        # ssh_keys veya _ssh grubunu bul
        ssh_group = None
        with open("/etc/group") as f:
            for line in f:
                if line.split(":")[0] in ["ssh_keys", "_ssh"]:
                    ssh_group = line.split(":")[0]
                    break

        for f in key_files:
            try:
                # Tüm dosyaları revert ederken varsayılan güvenli izinler
                if ssh_group:
                    run_command(["chmod", "600", f])  # güvenli varsayılan
                    run_command(["chown", "root:root", f])
                else:
                    run_command(["chmod", "600", f])
                    run_command(["chown", "root:root", f])
                reverted.append(f"{f} revert edildi")
            except Exception as e:
                failed.append(f"{f} hata: {str(e)}")

        ok, msg = check_ssh_private_host_key_permissions()
        if ok and not failed:
            logger.info("[CIS 5.1.2][REVERT] Tüm SSH private host key dosyaları revert edildi.")
            return True, "Revert tamamlandı: " + "; ".join(reverted)
        elif ok:
            logger.warning("[CIS 5.1.2][REVERT] Bazı dosyalar revert edilemedi: " + "; ".join(failed))
            return True, "Kısmen revert edildi: " + "; ".join(reverted) + " | Hatalar: " + "; ".join(failed)
        else:
            logger.error("[CIS 5.1.2][REVERT] Revert sonrası hâlâ hatalar var: " + msg)
            return False, "Revert sonrası hatalar var: " + msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.2][REVERT] {msg}")
        return False, f"SSH private host key revert hatası: {msg}"



def revert_ssh_public_host_key_permissions():
    """
    CIS 5.1.3 - SSH public host key dosyalarının revert işlemi.
    Varsayılan güvenli duruma (0644, root:root) geri döndürür.
    """
    try:
        key_files = find_ssh_public_host_keys()
        if not key_files:
            return True, "Public host key (.pub) dosyası bulunamadı, revert gerek yok."

        reverted, failed = [], []

        for f in key_files:
            try:
                ok1, out1 = run_command(["chmod", "644", f])
                ok2, out2 = run_command(["chown", "root:root", f])

                if not ok1:
                    failed.append(f"{f}: chmod revert başarısız ({out1})")
                    continue
                if not ok2:
                    failed.append(f"{f}: chown revert başarısız ({out2})")
                    continue

                reverted.append(f"{f}: revert 0644 ve root:root uygulandı")
            except Exception as e:
                failed.append(f"{f}: revert hatası ({e})")

        ok_after, msg_after = check_ssh_public_host_key_permissions()
        if ok_after and not failed:
            logger.info("[CIS 5.1.3][REVERT] Tüm SSH public host key dosyaları revert edildi.")
            return True, "Revert başarılı: " + "; ".join(reverted)
        elif ok_after:
            logger.warning("[CIS 5.1.3][REVERT] Bazı SSH public host key dosyaları revert edilemedi: " + "; ".join(failed))
            return True, "Kısmen revert: " + "; ".join(reverted) + " | Hatalar: " + "; ".join(failed)
        else:
            logger.error("[CIS 5.1.3][REVERT]Revert sonrası hâlâ hatalar var: " + msg_after)
            return False, "Revert sonrası hâlâ hatalar var: " + msg_after + " | İşlemler: " + "; ".join(reverted) + " | Hatalar: " + "; ".join(failed)

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.3][REVERT] {msg}")
        return False, f"SSH public host key revert hatası: {msg}"



def revert_sshd_access():
    """
    CIS 5.1.4 Revert: SSH access kısıtlamalarını geri al.
    Tüm AllowUsers, AllowGroups, DenyUsers, DenyGroups satırlarını kaldırır.
    """
    keys = ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]

    try:
        if not os.path.exists(SSHD_CONFIG):
            logger.info(f"[CIS 5.1.4][REVERT] {SSHD_CONFIG} bulunamadı, revert gereksiz.")
            return True, f"{SSHD_CONFIG} bulunamadı, revert gereksiz."

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        # İlgili satırları kaldır
        new_lines = [line for line in lines if not any(line.strip().lower().startswith(k.lower()) for k in keys)]

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        # SSH servisini yeniden yükle
        run_command(["systemctl", "reload", "sshd"])
        logger.info("[CIS 5.1.4][REVERT] SSH servisi reload edildi, Allow/Deny satırları kaldırıldı.")

        # Kontrol
        success, msg = check_sshd_access()
        if not success:
            logger.info("[CIS 5.1.4][REVERT] SSH access revert edildi, tüm Allow/Deny satırları kaldırıldı.")
            return True, "SSH access revert edildi, tüm Allow/Deny satırları kaldırıldı."
        else:
            logger.warning(f"[CIS 5.1.4][REVERT] SSH access revert edildi, kalan ayarlar: {msg}")
            return True, "SSH access revert edildi, kalan ayarlar: " + msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.4][REVERT] {msg}")
        return False, f"SSH access revert hatası: {msg}"


def revert_sshd_banner():
    """
    CIS 5.1.5 Revert: SSHD Banner ayarlarını geri al.
    Banner satırını sshd_config'den kaldırır ve banner dosyasını temizler.
    """
    try:
        # SSHD_CONFIG kontrolü
        if not os.path.exists(SSHD_CONFIG):
            logger.info(f"[CIS 5.1.5][REVERT] {SSHD_CONFIG} bulunamadı, revert gereksiz.")
            return True, f"{SSHD_CONFIG} bulunamadı, revert gereksiz."

        # SSHD_CONFIG içindeki Banner satırlarını kaldır
        updated_lines = []
        banner_found = False
        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().lower().startswith("banner "):
                    banner_found = True
                    continue  # satırı atla
                updated_lines.append(line)

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)

        # Banner dosyasını temizle (varsa)
        if os.path.exists(BANNER_FILE):
            with open(BANNER_FILE, "w", encoding="utf-8") as f:
                f.write("")
            logger.info(f"[CIS 5.1.5][REVERT] Banner dosyası {BANNER_FILE} temizlendi.")

        # SSH servisini yeniden başlat
        run_command(["systemctl", "restart", "sshd"])
        logger.info("[CIS 5.1.5][REVERT] SSH servisi restart edildi, Banner satırı kaldırıldı.")

        # Kontrol
        success, msg = check_sshd_banner()
        if not success:
            logger.info("[CIS 5.1.5][REVERT] Banner revert edildi, artık banner ayarı yok veya dosya boş.")
            return True, "Banner revert edildi, artık banner ayarı yok veya dosya boş."
        else:
            logger.warning(f"[CIS 5.1.5][REVERT] Banner revert edildi ama halen ayarlar var: {msg}")
            return True, "Banner revert edildi, kalan ayarlar: " + msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.5][REVERT] {msg}")
        return False, f"Banner revert hatası: {msg}"


def revert_sshd_ciphers():
    """
    CIS 5.1.6 Revert: SSHD Ciphers ayarlarını geri al.
    Backup yoksa varsayılan güvenli cipher listesine döner.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            logger.warning(f"[CIS 5.1.6][REVERT] {SSHD_CONFIG} bulunamadı, revert gereksiz.")
            return True, f"{SSHD_CONFIG} bulunamadı, revert gereksiz."

        backup_file = f"{SSHD_CONFIG}.bak"
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, SSHD_CONFIG)
            logger.info(f"[CIS 5.1.6][REVERT] Backup geri yüklendi: {backup_file}")
        else:
            # Backup yoksa varsayılan güvenli cipherleri uygula
            with open(SSHD_CONFIG, "r") as f:
                lines = f.readlines()

            updated_lines = []
            ciphers_set = False
            for line in lines:
                if line.strip().startswith("Ciphers"):
                    updated_lines.append(f"Ciphers {DEFAULT_CIPHERS}\n")
                    ciphers_set = True
                else:
                    updated_lines.append(line)

            if not ciphers_set:
                updated_lines.append(f"\nCiphers {DEFAULT_CIPHERS}\n")

            with open(SSHD_CONFIG, "w") as f:
                f.writelines(updated_lines)
            logger.info(f"[CIS 5.1.6][REVERT] Varsayılan güvenli ciphers uygulandı: {DEFAULT_CIPHERS}")

        # Config test (syntax check)
        success, output = run_command(["sshd", "-t"])
        if not success:
            logger.error(f"[CIS 5.1.6][REVERT] Config test hatası: {output}")
            return False, f"Config test hatası: {output}"

        # SSH servisini yeniden başlat
        success, output = run_command(["systemctl", "restart", "sshd"])
        if not success:
            logger.error(f"[CIS 5.1.6][REVERT] sshd restart başarısız: {output}")
            return False, f"sshd restart başarısız: {output}"

        # Kontrol
        ok, msg = check_sshd_ciphers(param={"ciphers": DEFAULT_CIPHERS})
        if ok:
            logger.info(f"[CIS 5.1.6][REVERT] Ciphers revert edildi: {msg}")
            return True, f"Ciphers revert edildi: {msg}"
        else:
            logger.warning(f"[CIS 5.1.6][REVERT] Revert sonrası doğrulama hatası: {msg}")
            return False, f"Revert sonrası doğrulama hatası: {msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.6][REVERT] {msg}")
        return False, f"Ciphers revert hatası: {msg}"


def revert_ssh_client_alive():
    """
    CIS 5.1.7 - ClientAlive ayarlarını revert et.
    Varsayılan veya önceki değerler bilinmiyorsa parametreleri kaldırır.
    """
    try:
        # Mevcut sshd_config'i oku
        content = read_sshd_config()
        lines = content.splitlines()
        new_lines = []

        for line in lines:
            # ClientAliveInterval ve ClientAliveCountMax satırlarını kaldır
            if line.strip().lower().startswith("clientaliveinterval") or \
               line.strip().lower().startswith("clientalivecountmax"):
                logger.info(f"[CIS 5.1.7][REVERT] Kaldırıldı: {line.strip()}")
                continue
            new_lines.append(line)

        write_sshd_config("\n".join(new_lines) + "\n")

        # SSHD servisini reload et
        success, msg = reload_sshd()
        if not success:
            logger.error(f"[CIS 5.1.7][REVERT] sshd reload başarısız: {msg}")
            return False, f"sshd reload başarısız: {msg}"

        ok, check_msg = check_ssh_client_alive(param={})
        if ok:
            logger.info(f"[CIS 5.1.7][REVERT] ClientAlive ayarları revert edildi.")
            return True, "ClientAlive ayarları revert edildi, tüm özel satırlar kaldırıldı."
        else:
            logger.warning(f"[CIS 5.1.7][REVERT] Revert sonrası kontrol uyarısı: {check_msg}")
            return True, f"ClientAlive ayarları revert edildi, uyarı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.7][REVERT] {msg}")
        return False, f"ClientAlive revert hatası: {msg}"


def revert_sshd_disableforwarding():
    """
    CIS 5.1.8 - SSH DisableForwarding revert fonksiyonu.
    DisableForwarding satırını sshd_config'den kaldırır.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            logger.warning(f"[CIS 5.1.8][REVERT] {SSHD_CONFIG} bulunamadı, revert yapılamadı.")
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        removed = False
        for line in lines:
            if line.strip().lower().startswith("disableforwarding"):
                removed = True
                logger.info(f"[CIS 5.1.8][REVERT] Kaldırıldı: {line.strip()}")
                continue
            new_lines.append(line)

        if removed:
            with open(SSHD_CONFIG, "w") as f:
                f.writelines(new_lines)

            success, output = run_command(["systemctl", "reload", "sshd"])
            if not success:
                logger.error(f"[CIS 5.1.8][REVERT] sshd reload başarısız: {output}")
                return False, f"sshd reload başarısız: {output}"

            ok, msg = check_sshd_disableforwarding()
            if not ok:
                logger.warning(f"[CIS 5.1.8][REVERT] Revert sonrası kontrol uyarısı: {msg}")
            return True, "DisableForwarding revert edildi."

        else:
            logger.info("[CIS 5.1.8][REVERT] DisableForwarding satırı bulunamadı, işlem yapılmadı.")
            return True, "DisableForwarding satırı bulunamadı, revert gerekmiyor."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.8][REVERT] {msg}")
        return False, f"DisableForwarding revert hatası: {msg}"



def revert_sshd_gssapiauthentication():
    """
    CIS 5.1.9 - GSSAPIAuthentication revert
    SSHD_CONFIG içinden GSSAPIAuthentication satırını kaldırır.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            logger.warning(f"[CIS 5.1.9][REVERT] {SSHD_CONFIG} bulunamadı.")
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r") as f:
            lines = f.readlines()

        new_lines = []
        removed = False
        for line in lines:
            if line.strip().lower().startswith("gssapiauthentication"):
                removed = True
                logger.info(f"[CIS 5.1.9][REVERT] Kaldırıldı: {line.strip()}")
                continue
            new_lines.append(line)

        with open(SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        # Kontrol
        ok, msg = check_sshd_gssapiauthentication()
        if ok:
            logger.warning(f"[CIS 5.1.9][REVERT] Revert sonrası kontrol uyarısı: {msg}")
            return True, f"Revert uygulandı, uyarı: {msg}"
        else:
            return True, "Revert uygulandı, GSSAPIAuthentication satırı kaldırıldı."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.9][REVERT] {msg}")
        return False, msg


def revert_sshd_hostbasedauthentication():
    """
    CIS 5.1.10 - Revert HostbasedAuthentication parametresini kaldırır.
    Default SSH davranışı (no) güvenli kabul edilir.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^\s*hostbasedauthentication\b', re.IGNORECASE)
        new_lines = [line for line in lines if not pattern.match(line.strip())]

        removed_count = len(lines) - len(new_lines)

        if removed_count == 0:
            logger.info("[CIS 5.1.10][REVERT] HostbasedAuthentication satırı zaten yok, revert gerekli değil.")
            return True, "HostbasedAuthentication revert edilmedi, zaten varsayılan değer kullanılıyor."

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.10][REVERT] Kaldırıldı: HostbasedAuthentication {removed_count} satır, varsayılan 'no' değerinde.")
        return True, f"HostbasedAuthentication revert edildi, {removed_count} satır kaldırıldı, sistem varsayılan 'no' değerde."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.10][REVERT] {msg}")
        return False, f"Revert sırasında hata: {msg}"


def revert_sshd_ignorerhosts():
    """
    CIS 5.1.11 - Revert IgnoreRhosts parametresini kaldırır.
    Default SSH davranışı (no) güvenli kabul edilir.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^\s*ignorerhosts\b', re.IGNORECASE)
        new_lines = [line for line in lines if not pattern.match(line.strip())]

        removed_count = len(lines) - len(new_lines)

        if removed_count == 0:
            logger.info("[CIS 5.1.11][REVERT] IgnoreRhosts satırı zaten yok, revert gerekli değil.")
            return True, "IgnoreRhosts revert edilmedi, zaten varsayılan değer kullanılıyor."

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.11][REVERT] Kaldırıldı: IgnoreRhosts {removed_count} satır, varsayılan 'no' değerinde.")
        return True, f"IgnoreRhosts revert edildi, {removed_count} satır kaldırıldı, sistem varsayılan 'no' değerde."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.11][REVERT] {msg}")
        return False, f"Revert sırasında hata: {msg}"


def revert_sshd_kexalgorithms():
    """
    CIS 5.1.12 - SSHD KexAlgorithms revert.
    Revert işlemi ile özel disable satırı kaldırılır, varsayılan algoritmalar kullanılacak.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^\s*kexalgorithms\b', re.IGNORECASE)
        new_lines = [line for line in lines if not pattern.match(line.strip())]

        removed_count = len(lines) - len(new_lines)

        if removed_count == 0:
            logger.info("[CIS 5.1.12][REVERT] KexAlgorithms özel satırı zaten yok, revert gerekli değil.")
            return True, "KexAlgorithms revert edilmedi, varsayılan algoritmalar kullanılıyor."

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.12][REVERT] Kaldırıldı: KexAlgorithms {removed_count} satır, varsayılan algoritmalar aktif.")
        return True, f"KexAlgorithms revert edildi, {removed_count} satır kaldırıldı, sistem varsayılan algoritmalar kullanıyor."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.12][REVERT] {msg}")
        return False, f"Revert sırasında hata: {msg}"



def revert_sshd_logingracetime():
    """
    CIS 5.1.13 - SSHD LoginGraceTime revert.
    Revert işlemi ile LoginGraceTime satırları silinir ve varsayılan davranış geri gelir.
    """
    conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
    removed_files = []
    failed_files = []

    try:
        for conf_file in conf_files:
            try:
                if os.path.exists(conf_file):
                    # Yedek al
                    shutil.copy2(conf_file, f"{conf_file}.bak")
                    # LoginGraceTime satırlarını kaldır
                    with open(conf_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    new_lines = [line for line in lines if not line.strip().lower().startswith("logingracetime")]
                    with open(conf_file, "w", encoding="utf-8") as f:
                        f.writelines(new_lines)
                    removed_files.append(conf_file)
            except Exception as e:
                failed_files.append(f"{conf_file} hata: {e}")

        # SSH servisini reload et
        run_command(["systemctl", "reload", "sshd"])

        msg = f"LoginGraceTime revert edildi. Düzenlenen dosyalar: {removed_files}"
        if failed_files:
            msg += f" | Hatalı dosyalar: {failed_files}"
            logger.warning(f"[CIS 5.1.13][REVERT] {msg}")
        else:
            logger.info(f"[CIS 5.1.13][REVERT] {msg}")

        return True, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.13][REVERT] {msg}")
        return False, f"LoginGraceTime revert hatası: {msg}"


def revert_sshd_loglevel():
    """
    CIS 5.1.14 - SSHD LogLevel revert.
    Revert işlemi ile LogLevel satırları kaldırılır ve varsayılan davranış geri gelir.
    """
    backup_files = []
    try:
        if os.path.exists(SSHD_CONFIG):
            backup_file = f"{SSHD_CONFIG}.bak"
            shutil.copy2(SSHD_CONFIG, backup_file)
            backup_files.append(backup_file)

            with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if not line.strip().lower().startswith("loglevel")]
            with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

        run_command(["systemctl", "reload", "sshd"])

        msg = "LogLevel revert edildi ve varsayılan değer kullanılıyor."
        if backup_files:
            msg += f" Yedek dosya: {backup_files[0]}"
        logger.info(f"[CIS 5.1.14][REVERT] {msg}")
        return True, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.14][REVERT] {msg}")
        return False, f"LogLevel revert hatası: {msg}"


def revert_sshd_macs():
    """
    CIS 5.1.15 - SSHD MACs revert.
    Mevcut MACs satırlarını kaldırır, revert sonrası varsayılan sistem davranışı geçerlidir.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        backup_file = BACKUP_CONFIG
        shutil.copy2(SSHD_CONFIG, backup_file)

        # Mevcut MACs satırlarını kaldır
        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().lower().startswith("macs")]

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # SSH servisini reload et
        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.15][REVERT] MACs revert edildi, varsayılan değer kullanılıyor. Yedek: {backup_file}")
        return True, f"MACs revert edildi, varsayılan değer kullanılıyor. Yedek: {backup_file}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.15][REVERT] {msg}")
        return False, f"MACs revert hatası: {msg}"


def revert_sshd_maxauthtries():
    """
    CIS 5.1.16 - SSHD MaxAuthTries revert
    MaxAuthTries satırını sshd_config'tan kaldırır, revert sonrası varsayılan değer geçerlidir.
    """
    try:
        if not os.path.exists(SSHD_CONFIG):
            return False, f"{SSHD_CONFIG} bulunamadı."

        # Yedek al
        backup_file = f"{SSHD_CONFIG}.bak"
        shutil.copy2(SSHD_CONFIG, backup_file)

        # Mevcut MaxAuthTries satırlarını kaldır
        with open(SSHD_CONFIG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().lower().startswith("maxauthtries")]

        with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # SSH servisini reload et
        run_command(["sudo", "systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.16][REVERT] MaxAuthTries revert edildi, varsayılan değer kullanılıyor. Yedek: {backup_file}")
        return True, f"MaxAuthTries revert edildi, varsayılan değer kullanılıyor. Yedek: {backup_file}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.16][REVERT] {msg}")
        return False, f"MaxAuthTries revert hatası: {msg}"


def revert_sshd_maxsessions():
    """
    CIS 5.1.17 - SSHD MaxSessions revert
    MaxSessions satırlarını sshd_config ve .d dizinindeki include dosyalarından kaldırır.
    Revert sonrası varsayılan değer geçerlidir.
    """
    try:
        conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        reverted_files = []

        for conf_file in conf_files:
            if not os.path.exists(conf_file):
                continue

            # Yedek al
            backup_file = f"{conf_file}.bak"
            shutil.copy2(conf_file, backup_file)

            # MaxSessions satırlarını kaldır
            with open(conf_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if not line.strip().lower().startswith("maxsessions")]

            with open(conf_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            reverted_files.append(conf_file)
            logger.info(f"[CIS 5.1.17][REVERT] MaxSessions satırı kaldırıldı: {conf_file}, yedek: {backup_file}")

        # SSH servisini reload et
        run_command(["sudo", "systemctl", "reload", "sshd"])

        return True, f"MaxSessions revert tamamlandı. Yedekler: {reverted_files}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.17][REVERT] {msg}")
        return False, f"MaxSessions revert hatası: {msg}"



def revert_sshd_maxstartups():
    """
    CIS 5.1.18 - SSHD MaxStartups revert
    MaxStartups satırlarını sshd_config ve include dizinlerinden kaldırır.
    Revert sonrası varsayılan değer geçerli olur.
    """
    try:
        conf_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        reverted_files = []

        for conf_file in conf_files:
            if not os.path.exists(conf_file):
                continue

            # Yedek al
            backup_file = f"{conf_file}.bak"
            shutil.copy2(conf_file, backup_file)

            # MaxStartups satırlarını kaldır
            with open(conf_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if not line.strip().lower().startswith("maxstartups")]

            with open(conf_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            reverted_files.append(conf_file)
            logger.info(f"[CIS 5.1.18][REVERT] MaxStartups satırı kaldırıldı: {conf_file}, yedek: {backup_file}")

        # SSH servisini reload et
        run_command(["sudo", "systemctl", "reload", "sshd"])

        return True, f"MaxStartups revert tamamlandı. Yedekler: {reverted_files}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.18][REVERT] {msg}")
        return False, f"MaxStartups revert hatası: {msg}"



def revert_sshd_permitemptypasswords():
    """
    CIS 5.1.19 - SSHD PermitEmptyPasswords revert
    PermitEmptyPasswords satırlarını sshd_config ve include dizinlerinden kaldırır.
    Revert sonrası varsayılan değer geçerli olur.
    """
    try:
        conf_files = [SSHD_CONFIG] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        reverted_files = []

        for conf_file in conf_files:
            if not os.path.exists(conf_file):
                continue

            # Yedek al
            backup_file = f"{conf_file}.bak"
            shutil.copy2(conf_file, backup_file)

            # PermitEmptyPasswords satırlarını kaldır
            with open(conf_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if not line.strip().lower().startswith("permitemptypasswords")]

            with open(conf_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            reverted_files.append(conf_file)
            logger.info(f"[CIS 5.1.19][REVERT] PermitEmptyPasswords satırı kaldırıldı: {conf_file}, yedek: {backup_file}")

        # SSH servisini reload et
        run_command(["sudo", "systemctl", "reload", "sshd"])

        return True, f"PermitEmptyPasswords revert tamamlandı. Yedekler: {reverted_files}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.19][REVERT] {msg}")
        return False, f"PermitEmptyPasswords revert hatası: {msg}"



def revert_sshd_permitrootlogin():
    """
    CIS 5.1.20 - SSHD PermitRootLogin revert
    PermitRootLogin satırlarını sshd_config ve include dizinlerinden kaldırır.
    Revert sonrası varsayılan değer geçerli olur.
    """
    try:
        conf_files = [SSHD_CONFIG] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        reverted_files = []

        for conf_file in conf_files:
            if not os.path.exists(conf_file):
                continue

            # Yedek al
            backup_file = f"{conf_file}.bak"
            shutil.copy2(conf_file, backup_file)

            # PermitRootLogin satırlarını kaldır
            with open(conf_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if not line.strip().lower().startswith("permitrootlogin")]

            with open(conf_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            reverted_files.append(conf_file)
            logger.info(f"[CIS 5.1.20][REVERT] PermitRootLogin satırı kaldırıldı: {conf_file}, yedek: {backup_file}")

        # SSH servisini reload et
        run_command(["sudo", "systemctl", "reload", "sshd"])

        return True, f"PermitRootLogin revert tamamlandı. Yedekler: {reverted_files}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.20][REVERT] {msg}")
        return False, f"PermitRootLogin revert hatası: {msg}"


def revert_sshd_permit_user_environment():
    """
    CIS 5.1.21 - SSHD PermitUserEnvironment revert
    PermitUserEnvironment satırlarını /etc/ssh/sshd_config dosyasından kaldırır.
    Revert sonrası varsayılan değer geçerli olur.
    """
    config_file = "/etc/ssh/sshd_config"
    try:
        if not os.path.exists(config_file):
            return False, f"{config_file} bulunamadı."

        backup_file = f"{config_file}.bak"
        shutil.copy2(config_file, backup_file)

        # PermitUserEnvironment satırlarını kaldır
        with open(config_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().lower().startswith("permituserenvironment")]

        with open(config_file, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # SSH servisini reload et
        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.21][REVERT] PermitUserEnvironment satırı kaldırıldı. Yedek: {backup_file}")
        return True, f"PermitUserEnvironment revert tamamlandı. Yedek: {backup_file}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.21][REVERT] {msg}")
        return False, f"PermitUserEnvironment revert hatası: {msg}"


def revert_sshd_usepam():
    """
    CIS 5.1.22 - SSHD UsePAM revert
    UsePAM satırlarını /etc/ssh/sshd_config dosyasından kaldırır.
    Revert sonrası varsayılan değer geçerli olur.
    """
    sshd_config = "/etc/ssh/sshd_config"
    try:
        if not os.path.exists(sshd_config):
            return False, f"{sshd_config} bulunamadı."

        backup_file = f"{sshd_config}.bak"
        shutil.copy2(sshd_config, backup_file)

        # UsePAM satırlarını kaldır
        with open(sshd_config, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().lower().startswith("usepam")]

        with open(sshd_config, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # SSH servisini reload et
        run_command(["systemctl", "reload", "sshd"])

        logger.info(f"[CIS 5.1.22][REVERT] UsePAM satırı kaldırıldı. Yedek: {backup_file}")
        return True, f"UsePAM revert tamamlandı. Yedek: {backup_file}. Varsayılan değer geçerli."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 5.1.22][REVERT] {msg}")
        return False, f"UsePAM revert hatası: {msg}"


###############  CIS HARICI POLITIKA REVERTLERI  #####################


def revert_ssh_key_authentication():
    """
    CIS 5.x.x - Revert SSH key-based authentication enforcement.
    (PasswordAuthentication ayarını içeren override dosyasını siler.)
    
    Uyarı: Bu işlem parolalı SSH girişini yeniden etkinleştirir ve güvenliği azaltır.
    """
    filename = "disable_password_auth.conf"
    dir_path = "/etc/ssh/sshd_config.d"
    full_path = os.path.join(dir_path, filename)

    logger.info(f"[SSH Key Auth][REVERT] Geri alma başlatıldı: {full_path}")

    if not os.path.exists(full_path):
        msg = f"Yapılandırma dosyası ({full_path}) zaten mevcut değil."
        logger.info(f"[SSH Key Auth][REVERT] {msg}")
        return True, msg

    try:
        os.remove(full_path)
        logger.info(f"[SSH Key Auth][REVERT] SSH override dosyası silindi: {full_path}")

        logger.info("[SSH Key Auth][REVERT] sshd servisi yeniden yükleniyor...")
        success_reload, output_reload = run_command(["systemctl", "reload", "sshd"])
        
        if not success_reload:

            logger.warning(f"[SSH Key Auth][REVERT] Yeniden yükleme başarısız: {output_reload}. Yeniden başlatma deneniyor...")
            success_reload, output_reload = run_command(["systemctl", "restart", "sshd"])
            
            if not success_reload:
                msg = f"sshd servisi yeniden yüklenemedi/başlatılamadı: {output_reload}"
                logger.error(f"[SSH Key Auth][REVERT] HATA: {msg}")
                return False, msg

        logger.info("[SSH Key Auth][REVERT] Parolalı SSH girişine yeniden izin verildi.")
        return True, "SSH parolalı kimlik doğrulaması başarıyla revert edildi ve sshd servisi güncellendi."

    except PermissionError:
        msg = "Yetki hatası: Dosya silme veya servis kontrolü için Root yetkisi gerekli."
        logger.error(f"[SSH Key Auth][REVERT] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Geri alma sırasında beklenmedik hata: {str(e)}"
        logger.error(f"[SSH Key Auth][REVERT] HATA: {msg}")
        return False, msg



def revert_ssh_port_to_default():
    """
    [REVERT][SSH PORT] SSH port yapılandırmasını sıfırlar ve SSH servisini varsayılan porta (22) döndürür.
    """
    try:
        conf_file = "/etc/ssh/sshd_config.d/ssh_port.conf"

        if os.path.exists(conf_file):
            os.remove(conf_file)
            logger.info("[REVERT][SSH PORT] %s dosyası silindi.", conf_file)
        else:
            logger.info("[REVERT][SSH PORT] %s dosyası bulunamadı, işlem yapılmadı.", conf_file)

        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            logger.info("[REVERT][SSH PORT] SSH portu varsayılan 22 olarak ayarlandı, servis yeniden başlatıldı.")
            return True, "SSH port yapılandırması sıfırlandı ve servis yeniden başlatıldı (varsayılan port 22 kullanılacak)."
        else:
            logger.error("[REVERT][SSH PORT] SSH servisi yeniden başlatılamadı: %s", output)
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        logger.error(f"[REVERT][SSH PORT] Hata: {e}")
        return False, f"SSH port sıfırlama hatası: {str(e)}"



def revert_restrict_ssh_to_ips():
    """
    [REVERT][SSH RESTRICT] restrict_ssh_to_ips politikasını geri alır.
    """
    try:
        sshd_conf_path = "/etc/ssh/sshd_config.d/restrict_ips.conf"

        if os.path.exists(sshd_conf_path):
            os.remove(sshd_conf_path)
            logger.info("[REVERT][SSH RESTRICT] %s dosyası silindi.", sshd_conf_path)
        else:
            logger.info("[REVERT][SSH RESTRICT] %s bulunamadı, işlem yapılmadı.", sshd_conf_path)

        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            logger.info("[REVERT][SSH RESTRICT] Politika geri alındı, SSH servisi yeniden başlatıldı (varsayılan ayar).")
            return True, "SSH erişim sınırlaması geri alındı, varsayılan ayarlar yüklendi."
        else:
            logger.error("[REVERT][SSH RESTRICT] SSH servisi yeniden başlatılamadı: %s", output)
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        logger.error("[REVERT][SSH RESTRICT] Hata: %s", e)
        return False, f"Revert hatası: {str(e)}"