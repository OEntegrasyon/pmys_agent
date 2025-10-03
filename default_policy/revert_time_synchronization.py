###############################################################################################################################
###                                                                                                                         ###
###                                             CIS TIME SYNCHRONIZATION REVERT                                             ###
###                                                                                                                         ###
###############################################################################################################################

import os

from logger import logger
from utils import run_command


def revert_timesyncd_service():
    """
    Revert - CIS 2.3.1.1
    Debian/Pardus varsayılanı olan chrony yeniden etkinleştirilir.
    systemd-timesyncd devre dışı bırakılır.
    """
    try:
        logger.info("[CIS 2.3.1.1][REVERT] timesyncd politikası geri alınıyor...")

        # systemd-timesyncd devre dışı bırak
        run_command(["systemctl", "stop", "systemd-timesyncd.service"])
        run_command(["systemctl", "disable", "systemd-timesyncd.service"])
        logger.info("[CIS 2.3.1.1][REVERT] systemd-timesyncd devre dışı bırakıldı.")

        # chrony paketi kurulu mu?
        success_chrony, output_chrony = run_command(["dpkg", "-s", "chrony"])
        if not success_chrony or "install ok installed" not in output_chrony:
            logger.info("[CIS 2.3.1.1][REVERT] Chrony paketi bulunamadı, kuruluyor...")
            run_command(["apt-get", "update"])
            run_command(["apt-get", "-y", "install", "chrony"])
            logger.info("[CIS 2.3.1.1][REVERT] Chrony paketi kuruldu.")

        # chrony servisini etkinleştir
        run_command(["systemctl", "enable", "--now", "chrony.service"])
        logger.info("[CIS 2.3.1.1][REVERT] Chrony servisi etkinleştirildi ve başlatıldı.")
        return True, "[CIS 2.3.1.1][REVERT] timesyncd politikası başarıyla geri alındı."

    except Exception as e:
        msg = f"Hata : {e}"
        logger.error(f"[CIS 2.3.1.1][REVERT] Politika geri alma hatası: {msg}")
        return False, f"Politika geri alma hatası: {msg}"

def revert_systemd_timesyncd_authorized_timeserver():
    """
    Revert - CIS 2.3.2.1
    systemd-timesyncd yetkili zaman sunucusu ayarlarını geri alır.
    (apply sırasında oluşturulan drop-in dosyası silinir)
    """
    TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
    TIMESYNCD_CONF_DIR = "/etc/systemd/timesyncd.conf.d"
    DROPIN_FILE = os.path.join(TIMESYNCD_CONF_DIR, "60-timesyncd.conf")
    try:
        if os.path.exists(DROPIN_FILE):
            os.remove(DROPIN_FILE)
            logger.info(f"[CIS 2.3.2.1][REVERT] Drop-in dosyası silindi: {DROPIN_FILE}")
            
            # Klasör boşsa temizleyelim
            if os.path.isdir(TIMESYNCD_CONF_DIR) and not os.listdir(TIMESYNCD_CONF_DIR):
                os.rmdir(TIMESYNCD_CONF_DIR)
                logger.info(f"[CIS 2.3.2.1][REVERT] Boş dizin silindi: {TIMESYNCD_CONF_DIR}")
        else:
            logger.info("[CIS 2.3.2.1][REVERT] Drop-in dosyası zaten mevcut değil, yapılacak bir şey yok.")

        # Servisi yeniden yükle
        run_command(["systemctl", "reload-or-restart", "systemd-timesyncd.service"])
        logger.info("[CIS 2.3.2.1][REVERT] systemd-timesyncd varsayılan ayarlarına döndü.")

        return True, "systemd-timesyncd yetkili zaman sunucusu ayarları geri alındı."
    except Exception as e:
        logger.error(f"[CIS 2.3.2.1][REVERT] Hata oluştu: {e}")
        return False, f"Hata oluştu: {e}"


def revert_timesyncd_service_enabled():
    """
    Revert - CIS 2.3.2.2
    systemd-timesyncd.service'in enable + active durumunu geri alır.
    (Servisi durdurur ve disable eder. Eğer servis yoksa zaten revert edilmiş sayılır.)
    """
    try:
        logger.info("[CIS 2.3.2.2][REVERT] systemd-timesyncd servisi durduruluyor...")
        run_command(["systemctl", "stop", "systemd-timesyncd.service"])

        logger.info("[CIS 2.3.2.2][REVERT] systemd-timesyncd servisi disable edilmeye çalışılıyor...")
        run_command(["systemctl", "disable", "systemd-timesyncd.service"])

        # Durum kontrolü
        success_active, active_status = run_command(
            ["systemctl", "is-active", "systemd-timesyncd.service"]
        )
        success_enabled, enabled_status = run_command(
            ["systemctl", "is-enabled", "systemd-timesyncd.service"]
        )

        # Aktiflik kontrolü
        if success_active and active_status.strip() != "active":
            active_ok = True
        elif not success_active and "could not be found" in active_status.lower():
            active_ok = True
        else:
            active_ok = False

        # Enable durumu kontrolü
        if success_enabled and enabled_status.strip() == "disabled":
            enabled_ok = True
        elif not success_enabled and ("no such file" in enabled_status.lower() or "not-found" in enabled_status.lower()):
            enabled_ok = True
        else:
            enabled_ok = False

        if active_ok and enabled_ok:
            logger.info("[CIS 2.3.2.2][REVERT] systemd-timesyncd başarıyla revert edildi (inactive + disabled veya mevcut değil).")
            return True, "systemd-timesyncd başarıyla revert edildi."
        else:
            logger.warning(f"[CIS 2.3.2.2][REVERT] Beklenen durum sağlanamadı (enabled={enabled_status}, active={active_status})")
            return False, f"Beklenen durum sağlanamadı (enabled={enabled_status}, active={active_status})."

    except Exception as e:
        logger.error(f"[CIS 2.3.2.2][REVERT] Hata oluştu: {e}")
        return False, f"Hata oluştu: {str(e)}"


def revert_chrony_authorized_timeserver():
    """
    Revert - CIS 2.3.3.1
    apply_chrony_authorized_timeserver ile yapılan değişiklikleri geri alır.
    (drop-in dosyasını siler ve chronyd servisini yeniden yükler)
    """
    SOURCES_DIR_CHRONY = "/etc/chrony/sources.d"
    DROPIN_FILE_CHRONY = os.path.join(SOURCES_DIR_CHRONY, "60-sources.sources")
    try:
        if os.path.exists(DROPIN_FILE_CHRONY):
            os.remove(DROPIN_FILE_CHRONY)
            logger.info(f"[CIS 2.3.3.1][REVERT] Drop-in dosyası silindi: {DROPIN_FILE_CHRONY}")

            # sources.d klasörü boşsa kaldır
            if os.path.isdir(SOURCES_DIR_CHRONY) and not os.listdir(SOURCES_DIR_CHRONY):
                os.rmdir(SOURCES_DIR_CHRONY)
                logger.info(f"[CIS 2.3.3.1][REVERT] Boş dizin silindi: {SOURCES_DIR_CHRONY}")
        else:
            logger.info("[CIS 2.3.3.1][REVERT] Drop-in dosyası mevcut değil, yapılacak bir şey yok.")

        # chronyd yeniden yükle
        run_command(["systemctl", "reload-or-restart", "chronyd"])
        logger.info("[CIS 2.3.3.1][REVERT] Chrony varsayılan ayarlarına döndü.")

        return True, "Chrony authorized timeserver ayarları geri alındı."
    except Exception as e:
        logger.error(f"[CIS 2.3.3.1][REVERT] Hata oluştu: {e}")
        return False, f"Hata oluştu: {e}"


def revert_chrony_running_as_chrony():
    """
    CIS 2.3.3.2 - Revert: Ensure chrony is running as user _chrony
    Yapılan değişiklikleri geri alır (config dosyasındaki 'user _chrony' satırını kaldırır).
    """
    chrony_conf = "/etc/chrony/chrony.conf"
    try:
        if not os.path.exists(chrony_conf):
            logger.error("[CIS 2.3.3.2][REVERT] chrony config dosyası bulunamadı.")
            return False, "chrony config dosyası bulunamadı."

        with open(chrony_conf, "r") as f:
            lines = f.readlines()

        new_lines = []
        removed = False
        for line in lines:
            if line.strip().startswith("user _chrony"):
                logger.info("[CIS 2.3.3.2][REVERT] 'user _chrony' satırı kaldırıldı.")
                removed = True
                continue
            new_lines.append(line)

        if removed:
            with open(chrony_conf, "w") as f:
                f.writelines(new_lines)

            success, output = run_command(["systemctl", "restart", "chrony"])
            if not success:
                logger.error(f"[CIS 2.3.3.2][REVERT] chrony restart başarısız: {output}")
                return False, f"chrony restart başarısız: {output}"

            logger.info("[CIS 2.3.3.2][REVERT] Değişiklikler geri alındı ve chrony yeniden başlatıldı.")
            return True, "Değişiklikler geri alındı."
        else:
            logger.warning("[CIS 2.3.3.2][REVERT] 'user _chrony' satırı zaten yoktu, değişiklik yapılmadı.")
            return True, "'user _chrony' satırı zaten yoktu."

    except Exception as e:
        logger.error(f"[CIS 2.3.3.2][REVERT] Hata: {str(e)}")
        return False, f"Hata: {str(e)}"



def revert_timesync_service():
    """
    CIS 2.3.3.3 - Revert: Ensure a time synchronization service is enabled and running
    Yapılan değişiklikleri geri alır:
        - Etkinleştirilmiş ve çalışan servisleri durdurur ve disable eder.
        - Eğer systemd-timesyncd ise unmask yerine mask yapılır.
    """
    services = {
        "chrony": "chrony.service",
        "ntp": "ntp.service",
        "systemd-timesyncd": "systemd-timesyncd.service"
    }

    try:
        reverted = False
        for name, unit in services.items():
            ok1, out1 = run_command(["systemctl", "is-enabled", unit])
            ok2, out2 = run_command(["systemctl", "is-active", unit])

            if out1.strip() == "enabled" or out2.strip() == "active":

                run_command(["systemctl", "stop", unit])
                run_command(["systemctl", "disable", unit])

                if name == "systemd-timesyncd":
                    run_command(["systemctl", "mask", unit])

                reverted = True

        if reverted:
            logger.info("[CIS 2.3.3.3][REVERT] Etkin servis(ler) devre dışı bırakıldı.")
            return True, "Etkin servis(ler) devre dışı bırakıldı."
        else:
            logger.warning("[CIS 2.3.3.3][REVERT] Zaten etkin bir servis bulunamadı.")
            return True, "Zaten etkin bir servis bulunamadı."

    except Exception as e:
        logger.error(f"[CIS 2.3.3.3][REVERT] Hata: {str(e)}")
        return False, f"Hata: {str(e)}"