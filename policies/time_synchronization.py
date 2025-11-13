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
    CIS 2.3.1.1 - Ensure a single time synchronization daemon is in use
    chrony ve systemd-timesyncd servislerinden yalnızca birinin etkin ve aktif olduğunu kontrol eder.
    """
    daemons = {
        "systemd-timesyncd.service": "systemd-timesyncd",
        "chrony.service": "chrony",
    }

    active = []

    for svc, name in daemons.items():
        success_active, active_status = run_command(["systemctl", "is-active", svc])
        success_enabled, enabled_status = run_command(["systemctl", "is-enabled", svc])

        if (success_active and active_status.strip() == "active") and \
           (success_enabled and enabled_status.strip() in ["enabled", "static"]):
            active.append(name)

    if len(active) == 0:
        logger.warning("[CHECK] Hiçbir zaman senkronizasyon servisi aktif değil!")
        return False, "Hiçbir zaman senkronizasyon servisi aktif değil."
    elif len(active) > 1:
        logger.warning(f"[CHECK] Birden fazla zaman senkronizasyon servisi aktif: {', '.join(active)}")
        return False, f"Birden fazla zaman senkronizasyon servisi aktif: {', '.join(active)}"
    else:
        logger.info(f"[CHECK] CIS uyumlu: yalnızca {active[0]} aktif.")
        return True, f"Yalnızca {active[0]} aktif – CIS uyumlu."


def apply_timesyncd_service(username=None, param=None):
    """
    CIS 2.3.1.1 - Ensure a single time synchronization daemon is in use
    chrony veya systemd-timesyncd servislerinden yalnızca birini etkinleştirir,
    diğerini sistemden kaldırır veya devre dışı bırakır.
    """
    preferred = (param or {}).get("preferred_daemon", "systemd-timesyncd").lower()

    daemons = {
        "chrony": "chrony.service",
        "systemd-timesyncd": "systemd-timesyncd.service",
    }

    if preferred not in daemons:
        return False, f"Bilinmeyen daemon: {preferred}"

    try:
        logger.info(f"[APPLY] CIS 2.3.1.1 - {preferred} tercih edildi, mevcut durum kontrol ediliyor...")

        ok, msg = check_timesyncd_service()
        if ok:
            logger.info(f"[APPLY] Zaten uyumlu: {msg}")
            return True, f"Zaten uyumlu: {msg}"

        logger.info(f"[APPLY] Uyumlu değil, düzeltme işlemi başlatılıyor ({preferred})...")

        for name, svc in daemons.items():
            if name != preferred:
                run_command(["systemctl", "stop", svc])
                run_command(["systemctl", "disable", svc])
                run_command(["systemctl", "mask", svc])
                run_command(["apt-get", "-y", "purge", name])
                run_command(["apt-get", "-y", "autoremove"])
                logger.info(f"[APPLY] {name} servisi ve paketi kaldırıldı.")

        success_pkg, pkg_status = run_command(["dpkg", "-s", preferred])
        if not success_pkg or "install ok installed" not in pkg_status:
            logger.info(f"[APPLY] {preferred} paketi yüklü değil, yükleniyor...")
            run_command(["apt-get", "update", "-y"])
            run_command(["apt-get", "-y", "install", preferred])
            logger.info(f"[APPLY] {preferred} paketi yüklendi.")

        svc = daemons[preferred]
        run_command(["systemctl", "unmask", svc])
        run_command(["systemctl", "enable", "--now", svc])
        logger.info(f"[APPLY] {preferred} servisi etkinleştirildi ve başlatıldı.")

        ok, msg = check_timesyncd_service()
        if ok:
            logger.info(f"[APPLY] CIS uyumlu hale getirildi: {msg}")
            return True, f"CIS uyumlu hale getirildi: {msg}"
        else:
            logger.warning(f"[APPLY] Düzeltme sonrası uyumsuzluk devam ediyor: {msg}")
            return False, msg

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
                    if not stripped or stripped.startswith("#"):
                        continue
                    for srv in expected_servers:
                        if stripped.lower().startswith(("server", "pool")) and srv.lower() in stripped.lower():
                            found[srv] = True
                            logger.info(f"Bulundu: {srv} (dosya: {f})")
        except FileNotFoundError:
            continue

    if all(found.values()):
        return True, f"Chrony tüm yetkili sunucularla yapılandırılmış: {', '.join(expected_servers)}"
    else:
        eksikler = [srv for srv, ok in found.items() if not ok]
        return False, f"Eksik/hatalı timeserver(lar): {', '.join(eksikler)} | Dosyalar: {', '.join(files_to_check)}"


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

        if os.path.exists(DROPIN_FILE_CHRONY):
            shutil.copy(DROPIN_FILE_CHRONY, DROPIN_FILE_CHRONY + ".bak")

        servers = []
        if "ntp_server" in param:
            servers.append(param["ntp_server"])
        if "fallback_servers" in param:
            servers.extend(param["fallback_servers"])

        with open(DROPIN_FILE_CHRONY, "w") as f:
            f.write("# CIS 2.3.3.1 - Authorized timeservers\n")
            for srv in servers:
                f.write(f"server {srv} iburst\n")
        os.chmod(DROPIN_FILE_CHRONY, 0o644)

        success, output = run_command(["systemctl", "reload-or-restart", "chronyd"])
        if not success:
            return False, f"chronyd yeniden yüklenemedi: {output}"

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
    CIS 2.3.3.3 - Ensure chrony is enabled and running
    """
    ok1, out1 = run_command(["systemctl", "is-enabled", "chrony.service"])
    ok2, out2 = run_command(["systemctl", "is-active", "chrony.service"])

    if out1.strip() == "enabled" and out2.strip() == "active":
        logger.info("[CIS 2.3.3.3][CHECK] chrony servisi etkin ve çalışıyor.")
        return True, "chrony servisi etkin ve çalışıyor."
    else:
        logger.warning(f"[CIS 2.3.3.3][CHECK] chrony uygun değil (enabled={out1}, active={out2})")
        return False, "chrony servisi etkin değil veya çalışmıyor."


def apply_timesync_service(username=None, param=None):
    """
    CIS 2.3.3.3 - Ensure chrony is enabled and running
    """
    ok, msg = check_timesync_service()
    if ok:
        return True, msg

    try:
        run_command(["systemctl", "unmask", "chrony.service"])
        run_command(["systemctl", "--now", "enable", "chrony.service"])
        ok, msg = check_timesync_service()
        if ok:
            return True, "chrony servisi etkinleştirildi ve başlatıldı."
        else:
            return False, "chrony servisi başlatılamadı."
    except Exception as e:
        return False, f"Hata: {e}"