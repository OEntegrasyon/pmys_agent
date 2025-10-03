###############################################################################################################################
###                                                                                                                         ###
###                                             CIS TIME SYNCHRONIZATION GÜVENLİK AYARLARI                                  ###
###                                                                                                                         ###
###############################################################################################################################


import os

from utils import run_command
from logger import logger



def check_timesyncd_service():
    """
    CIS 2.3.1.1 - Ensure only systemd-timesyncd is in use
    systemd-timesyncd servisinin aktif ve enable durumda olup olmadığını kontrol eder.
    """
    success_enabled, enabled_status = run_command(
        ["systemctl", "is-enabled", "systemd-timesyncd.service"]
    )
    success_active, active_status = run_command(
        ["systemctl", "is-active", "systemd-timesyncd.service"]
    )

    if (success_enabled and enabled_status.strip() == "enabled") and \
       (success_active and active_status.strip() == "active"):
        logger.info("[CHECK] systemd-timesyncd servisi etkin ve çalışıyor.")
        return True, "systemd-timesyncd servisi etkin ve çalışıyor."
    else:
        logger.warning("[CHECK] systemd-timesyncd servisi etkin değil veya çalışmıyor.")
        return False, "systemd-timesyncd servisi etkin değil veya çalışmıyor."


def apply_timesyncd_service(username=None, param=None):
    """
    CIS 2.3.1.1 - Remediation
    Chrony/NTP devre dışı bırakılır ve sadece systemd-timesyncd etkinleştirilir.
    Eğer systemd-timesyncd paketi yüklü değilse yüklenir.
    """
    try:
        ok, msg = check_timesyncd_service()
        if ok:
            logger.info("[APPLY] Zaten uyumlu: " + msg)
            return True, msg

        logger.info("[APPLY] Uyumlu değil, düzeltme başlatılıyor...")

        # chrony durdur ve kaldır
        run_command(["systemctl", "stop", "chrony.service"])
        run_command(["systemctl", "disable", "chrony.service"])
        run_command(["apt-get", "-y", "purge", "chrony"])
        logger.info("[APPLY] Chrony paketi ve servisi kaldırıldı.")

        # ntp durdur ve kaldır
        run_command(["systemctl", "stop", "ntp.service"])
        run_command(["systemctl", "disable", "ntp.service"])
        run_command(["apt-get", "-y", "purge", "ntp"])
        logger.info("[APPLY] NTP paketi ve servisi kaldırıldı.")

        # systemd-timesyncd paket kontrolü
        success_pkg, pkg_status = run_command(["dpkg", "-s", "systemd-timesyncd"])
        if not success_pkg or "install ok installed" not in pkg_status:
            logger.info("[APPLY] systemd-timesyncd paketi bulunamadı, yükleniyor...")
            run_command(["apt-get", "update"])
            run_command(["apt-get", "-y", "install", "systemd-timesyncd"])
            logger.info("[APPLY] systemd-timesyncd paketi yüklendi.")

        # systemd-timesyncd etkinleştir
        run_command(["systemctl", "unmask", "systemd-timesyncd.service"])
        run_command(["systemctl", "enable", "--now", "systemd-timesyncd.service"])
        logger.info("[APPLY] systemd-timesyncd servisi etkinleştirildi.")

        ok, msg = check_timesyncd_service()
        if ok:
            return True, "systemd-timesyncd başarıyla etkinleştirildi."
        else:
            return False, "systemd-timesyncd etkinleştirilemedi!"

    except Exception as e:
        logger.error(f"[APPLY] Politika hatası: {e}")
        return False, f"Politika hatası: {e}"



TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
TIMESYNCD_CONF_DIR = "/etc/systemd/timesyncd.conf.d"
DROPIN_FILE = os.path.join(TIMESYNCD_CONF_DIR, "60-timesyncd.conf")


def check_systemd_timesyncd_authorized_timeserver(ntp_server, fallback_servers):
    """
    CIS 2.3.2.1 - Ensure systemd-timesyncd configured with authorized timeserver
    ntp_server: str, örn: "192.168.1.100"
    fallback_servers: list[str], örn: ["192.168.1.101", "192.168.1.102"]
    """
    files_to_check = [TIMESYNCD_CONF]

    if os.path.isdir(TIMESYNCD_CONF_DIR):
        for fname in os.listdir(TIMESYNCD_CONF_DIR):
            if fname.endswith(".conf"):
                files_to_check.append(os.path.join(TIMESYNCD_CONF_DIR, fname))

    found = {"NTP": False, "FallbackNTP": False}

    for f in files_to_check:
        try:
            with open(f, "r") as conf:
                for line in conf:
                    stripped = line.strip()
                    if stripped.startswith("NTP=") and ntp_server in stripped:
                        found["NTP"] = True
                        logger.info(f"[check] NTP bulundu: {stripped} (dosya: {f})")
                    if stripped.startswith("FallbackNTP="):
                        ok = all(srv in stripped for srv in fallback_servers)
                        if ok:
                            found["FallbackNTP"] = True
                            logger.info(f"[check] FallbackNTP bulundu: {stripped} (dosya: {f})")
        except FileNotFoundError:
            continue

    if all(found.values()):
        return True, "systemd-timesyncd yetkili zaman sunucuları ile yapılandırılmış."
    else:
        return False, "systemd-timesyncd için yetkili zaman sunucuları eksik veya hatalı."


def apply_systemd_timesyncd_authorized_timeserver(username=None, param=None):
    """
    CIS 2.3.2.1 - Remediation
    Parametreyle verilen NTP ve Fallback sunucularını konfigüre eder.
    """
    param = param or {}
    ntp_server = param.get("ntp_server", "").strip()
    fallback_servers = param.get("fallback_servers", [])
    ok, msg = check_systemd_timesyncd_authorized_timeserver(ntp_server, fallback_servers)
    if ok:
        logger.info("[apply] Zaten uyumlu: " + msg)
        return True, msg

    try:
        if not os.path.exists(TIMESYNCD_CONF_DIR):
            os.makedirs(TIMESYNCD_CONF_DIR, exist_ok=True)

        with open(DROPIN_FILE, "w") as f:
            f.write("[Time]\n")
            f.write(f"NTP={ntp_server}\n")
            f.write(f"FallbackNTP={' '.join(fallback_servers)}\n")

        run_command(["systemctl", "reload-or-restart", "systemd-timesyncd.service"])

        logger.info("[apply] systemd-timesyncd yetkili zaman sunucuları ile yapılandırıldı.")
        return True, "systemd-timesyncd yetkili zaman sunucuları ile yapılandırıldı."
    except Exception as e:
        logger.error(f"[apply] Hata oluştu: {e}")
        return False, f"Hata oluştu: {e}"



def check_timesyncd_service_enabled():
    """
    CIS 2.3.2.2: Ensure systemd-timesyncd is enabled and running.
    Beklenen: systemd-timesyncd.service enabled ve active durumda olmalı.
    """
    try:
        success_enabled, enabled_status = run_command(
            ["systemctl", "is-enabled", "systemd-timesyncd.service"]
        )
        if not success_enabled:
            return False, f"systemd-timesyncd enable durumu okunamadı: {enabled_status}"

        success_active, active_status = run_command(
            ["systemctl", "is-active", "systemd-timesyncd.service"]
        )
        if not success_active:
            return False, f"systemd-timesyncd active durumu okunamadı: {active_status}"

        if enabled_status.strip() == "enabled" and active_status.strip() == "active":
            return True, "systemd-timesyncd.service aktif ve enable durumda."
        else:
            return False, f"systemd-timesyncd durumu uygun değil (enabled={enabled_status}, active={active_status})."

    except Exception as e:
        return False, f"systemd-timesyncd kontrol hatası: {str(e)}"


def apply_timesyncd_service_enabled(username=None, param=None):
    """
    CIS 2.3.2.2: Ensure systemd-timesyncd is enabled and running.
    Gerekirse unmask + enable + start yapılır.
    """
    try:
        check_ok, check_msg = check_timesyncd_service()
        if check_ok:
            return True, check_msg

        run_command(["systemctl", "unmask", "systemd-timesyncd.service"])
        
        run_command(["systemctl", "--now", "enable", "systemd-timesyncd.service"])

        check_ok, check_msg = check_timesyncd_service()
        if check_ok:
            return True, f"systemd-timesyncd düzeltildi: {check_msg}"
        else:
            return False, f"systemd-timesyncd düzeltilemedi: {check_msg}"

    except Exception as e:
        return False, f"systemd-timesyncd uygulama hatası: {str(e)}"



CHRONY_CONF = "/etc/chrony/chrony.conf"
SOURCES_DIR_CHRONY = "/etc/chrony/sources.d"
DROPIN_FILE_CHRONY = os.path.join(SOURCES_DIR_CHRONY, "60-sources.sources")


def check_chrony_authorized_timeserver(param=None):
    """
    CIS 2.3.3.1 - Ensure chrony is configured with authorized timeserver
    Kontrol: chrony.conf veya sources.d altında server/pool direktifi var mı?
    Param ile gelen ntp_server ve fallback_servers değerleriyle doğrular.
    """
    if not param:
        return False, "Kontrol için timeserver parametresi verilmedi."

    expected_servers = []
    if "ntp_server" in param:
        expected_servers.append(param["ntp_server"])
    if "fallback_servers" in param:
        expected_servers.extend(param["fallback_servers"])

    files_to_check = [CHRONY_CONF]
    if os.path.isdir(SOURCES_DIR_CHRONY):
        for fname in os.listdir(SOURCES_DIR_CHRONY):
            if fname.endswith(".sources"):
                files_to_check.append(os.path.join(SOURCES_DIR_CHRONY, fname))

    found = {srv: False for srv in expected_servers}

    for f in files_to_check:
        try:
            with open(f, "r") as conf:
                for line in conf:
                    stripped = line.strip()
                    for srv in expected_servers:
                        if stripped.startswith(("server", "pool")) and srv in stripped:
                            found[srv] = True
                            logger.info(f"[check_chrony_authorized_timeserver] Bulundu: {stripped} (dosya: {f})")
        except FileNotFoundError:
            continue

    if all(found.values()):
        return True, "Chrony yetkili zaman sunucuları ile yapılandırılmış."
    else:
        eksikler = [srv for srv, ok in found.items() if not ok]
        return False, f"Chrony için eksik veya hatalı timeserver(lar): {', '.join(eksikler)}"



def apply_chrony_authorized_timeserver(username=None, param=None):
    """
    CIS 2.3.3.1 - Remediation
    Gelen param içindeki ntp_server + fallback_servers değerlerini
    /etc/chrony/sources.d/60-sources.sources dosyasına yazar ve chronyd'i reload eder.
    
    Param formatı:
    {
        "ntp_server": "time-a-g.nist.gov",
        "fallback_servers": ["132.163.97.3", "time-d-b.nist.gov"]
    }
    """
    if not param:
        return False, "Timeserver parametresi verilmedi."

    try:
        
        ok, msg = check_chrony_authorized_timeserver(param=param)
        if ok:
            logger.info("[apply_chrony_authorized_timeserver] Zaten uyumlu: " + msg)
            return True, msg

        if not os.path.exists(SOURCES_DIR_CHRONY):
            os.makedirs(SOURCES_DIR_CHRONY, exist_ok=True)

        servers = []
        if "ntp_server" in param:
            servers.append(param["ntp_server"])
        if "fallback_servers" in param:
            servers.extend(param["fallback_servers"])

        with open(DROPIN_FILE_CHRONY, "w") as f:
            f.write("# CIS 2.3.3.1 - Authorized timeservers\n")
            for srv in servers:
                f.write(f"server {srv} iburst\n")

        run_command(["systemctl", "reload-or-restart", "chronyd"])

        logger.info("[apply_chrony_authorized_timeserver] Chrony authorized timeserver ile yapılandırıldı.")
        return True, "Chrony authorized timeserver ile yapılandırıldı."

    except Exception as e:
        logger.error(f"[apply_chrony_authorized_timeserver] Hata oluştu: {e}")
        return False, f"Hata oluştu: {e}"



def check_chrony_running_as_chrony():
    """
    CIS 2.3.3.2 - Ensure chrony is running as user _chrony
    Audit eşdeğeri: ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }'
    """
    success, output = run_command(["ps", "-eo", "user:20,comm"])

    if not success:
        logger.error(f"[CIS 2.3.3.2][CHECK] ps komutu çalıştırılamadı: {output}")
        return False

    wrong_users = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            user, cmd = parts[0], parts[1]
            if cmd == "chronyd" and user != "_chrony":
                wrong_users.append(user)

    if wrong_users:
        logger.warning(f"[CIS 2.3.3.2][CHECK] chronyd yanlış kullanıcı ile çalışıyor: {', '.join(wrong_users)}")
        return False

    logger.info("[CIS 2.3.3.2][CHECK] chronyd doğru şekilde _chrony kullanıcısı ile çalışıyor.")
    return True




def apply_chrony_running_as_chrony(username=None, param=None):
    """
    CIS 2.3.3.2 - Ensure chrony is running as user _chrony
    """
    if check_chrony_running_as_chrony():
        logger.info("[CIS 2.3.3.2][APPLY] Değişiklik gerekmedi, zaten uyumlu.")
        return True, "Zaten uyumlu."

    chrony_conf = "/etc/chrony/chrony.conf"
    updated = False

    try:
        if not os.path.exists(chrony_conf):
            logger.error("[CIS 2.3.3.2][APPLY] chrony config dosyası bulunamadı.")
            return False, "chrony config dosyası bulunamadı."

        with open(chrony_conf, "r") as f:
            lines = f.readlines()

        new_lines = []
        found = False
        for line in lines:
            if line.strip().startswith("user "):
                new_lines.append("user _chrony\n")
                found = True
                updated = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append("user _chrony\n")
            updated = True

        if updated:
            with open(chrony_conf, "w") as f:
                f.writelines(new_lines)

            run_command(["systemctl", "restart", "chrony"])
            logger.info("[CIS 2.3.3.2][APPLY] chrony user _chrony olarak ayarlandı ve yeniden başlatıldı.")
        else:
            logger.info("[CIS 2.3.3.2][APPLY] Config zaten uyumlu.")

        return True, "chrony user ayarı uygulandı."

    except Exception as e:
        logger.error(f"[CIS 2.3.3.2][APPLY] Hata: {str(e)}")
        return False, f"Hata: {str(e)}"



def check_timesync_service():
    """
    CIS 2.3.3.3 - Ensure a time synchronization service is enabled and running
    Desteklenen servisler:
        - chrony
        - ntp
        - systemd-timesyncd
    """
    services = {
        "chrony": "chrony.service",
        "ntp": "ntp.service",
        "systemd-timesyncd": "systemd-timesyncd.service"
    }

    for name, unit in services.items():
        ok1, out1 = run_command(["systemctl", "is-enabled", unit])
        ok2, out2 = run_command(["systemctl", "is-active", unit])

        if out1.strip() == "enabled" and out2.strip() == "active":
            logger.info(f"[CIS 2.3.3.3][CHECK] {name} servisi etkin ve çalışıyor.")
            return True

    logger.warning("[CIS 2.3.3.3][CHECK] Uyumlu bir zaman senkronizasyon servisi çalışmıyor.")
    return False


def apply_timesync_service(username=None, param=None):
    """
    CIS 2.3.3.3 - Ensure a time synchronization service is enabled and running
    Remediation:
        - chrony, ntp veya systemd-timesyncd servislerinden biri etkinleştirilir
    """
    try:
        if check_timesync_service():
            msg = "Zaten uyumlu bir zaman senkronizasyon servisi çalışıyor."
            logger.info(f"[CIS 2.3.3.3][APPLY] {msg}")
            return True, msg

        # Öncelik: chrony -> ntp -> systemd-timesyncd
        preferred = [
            ("chrony", ["apt", "install", "-y", "chrony"], "chrony.service"),
            ("ntp", ["apt", "install", "-y", "ntp"], "ntp.service"),
            ("systemd-timesyncd", ["apt", "install", "-y", "systemd-timesyncd"], "systemd-timesyncd.service"),
        ]

        for name, install_cmd, unit in preferred:
            ok, out = run_command(["dpkg", "-l", name])
            if not ok:  # paket kurulu değilse yükle
                run_command(install_cmd)

            run_command(["systemctl", "unmask", unit])
            run_command(["systemctl", "--now", "enable", unit])

            if check_timesync_service():
                msg = f"{name} servisi etkinleştirildi ve başlatıldı."
                logger.info(f"[CIS 2.3.3.3][APPLY] {msg}")
                return True, msg

        msg = "Hiçbir zaman senkronizasyon servisi başlatılamadı!"
        logger.error(f"[CIS 2.3.3.3][APPLY] {msg}")
        return False, msg

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.3.3.3][APPLY] {msg}")
        return False, msg