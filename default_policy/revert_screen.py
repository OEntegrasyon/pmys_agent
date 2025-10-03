from utils import run_command
from logger import logger

from utils import (
    get_display_and_dbus_env,
    detect_desktop_env_from_processes
)

from policies.screen import (
    _get_gsettings_env)


def revert_screensaver_timeout(default_minutes: int = 30):
    """
    GNOME screensaver timeout değerini varsayılana döndürür.
    """
    try:
        saniye = default_minutes * 60
        success, output = run_command([
            "gsettings", "set", "org.gnome.desktop.session", "idle-delay", str(saniye)
        ])
        if success:
            logger.info(f"[REVERT] Screensaver timeout {default_minutes} dk olarak sıfırlandı.")
            return True, f"Screensaver timeout {default_minutes} dk olarak sıfırlandı."
        else:
            logger.error(f"[REVERT] Başarısız: {output}")
            return False, f"Sıfırlama başarısız: {output}"
    except Exception as e:
        logger.error(f"[REVERT] Hata: {str(e)}")
        return False, f"Revert hatası: {str(e)}"



def revert_auto_lock_screen(default_minutes: int = 10):
    """
    Otomatik ekran kilidini varsayılan süreye döndürür.
    """
    try:
        saniye = default_minutes * 60
        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()

        if not user or not display or not dbus:
            logger.error("[REVERT] Ortam değişkenleri alınamadı.")
            return False, "Ortam değişkenleri alınamadı."

        env_prefix = f"DISPLAY={display} DBUS_SESSION_BUS_ADDRESS={dbus}"

        if "gnome" in session_type:
            cmd = f"{env_prefix} gsettings set org.gnome.desktop.session idle-delay {saniye}"
        elif "xfce" in session_type:
            cmd = f"{env_prefix} xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s {default_minutes}"
        else:
            logger.warning(f"[REVERT] Desteklenmeyen masaüstü: {session_type}")
            return False, f"Desteklenmeyen masaüstü: {session_type}"

        success, output = run_command(["sudo", "-u", user, "bash", "-c", cmd])
        if success:
            logger.info(f"[REVERT] Ekran kilidi varsayılan {default_minutes} dk olarak sıfırlandı.")
            return True, f"Ekran kilidi {default_minutes} dk olarak sıfırlandı."
        else:
            logger.error(f"[REVERT] Başarısız: {output}")
            return False, f"Sıfırlama başarısız: {output}"
    except Exception as e:
        logger.error(f"[REVERT] Hata: {str(e)}")
        return False, f"Revert hatası: {str(e)}"



def revert_gnome_wallpaper_lockdown():
    """
    GNOME duvar kağıdı kilitleme politikasını geri alır.
    """
    try:
        files_to_remove = [
            "/etc/dconf/db/local.d/00-background-settings",
            "/etc/dconf/db/local.d/locks/background-lock",
        ]

        for f in files_to_remove:
            if os.path.exists(f):
                logger.info(f"[revert_gnome_wallpaper_lockdown] Dosya siliniyor: {f}")
                run_command(["sudo", "rm", "-f", f])
            else:
                logger.warning(f"[revert_gnome_wallpaper_lockdown] Dosya zaten yok: {f}")

        run_command(["sudo", "dconf", "update"])

        return True, "GNOME duvar kağıdı kilit politikası geri alındı."

    except Exception as e:
        logger.error(f"[revert_gnome_wallpaper_lockdown] Hata: {e}")
        return False, f"Revert hatası: {str(e)}"


def revert_gnome_desktop_icon_policy():
    """
    GNOME masaüstü simgeleri politikasını geri alır.
    """
    try:
        files_to_remove = [
            "/etc/dconf/db/local.d/00-desktop-icons-policy",
            "/etc/dconf/db/local.d/locks/desktop-icons-lock"
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                logger.info(f"[revert_gnome_desktop_icon_policy] Siliniyor: {f}")
                run_command(["sudo", "rm", "-f", f])
            else:
                logger.warning(f"[revert_gnome_desktop_icon_policy] Dosya zaten yok: {f}")

        run_command(["sudo", "dconf", "update"])

        return True, "Masaüstü simgeleri politikası geri alındı."

    except Exception as e:
        logger.error(f"[revert_gnome_desktop_icon_policy] Hata: {e}")
        return False, f"Revert hatası: {str(e)}"
