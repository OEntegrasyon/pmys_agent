from utils import run_command
from logger import logger

from utils import (
    get_logged_in_user,
    get_display_and_dbus_env,
    detect_desktop_env_from_processes
)


DEFAULT_SCREENSAVER_IMAGE = "file:///opt/screensaver.jpg"

DEFAULT_LOCK_DELAY = 5

def _parse_param_to_dict(param):
    """Parametreyi dict'e dönüştürür (str JSON veya dict)."""
    if param is None:
        return {}
    if isinstance(param, dict):
        return param
    if isinstance(param, str):
        try:
            return json.loads(param)
        except json.JSONDecodeError:
            logger.warning("[screensaver] Parametre JSON değil, boş dict olarak kabul ediliyor.")
            return {}
    logger.warning("[screensaver] Parametre tipi beklenmeyen türde, boş dict kullanılıyor.")
    return {}

def _get_gsettings_env():
    """
    get_display_and_dbus_env() -> (user, DISPLAY, DBUS_SESSION_BUS_ADDRESS)
    """
    try:
        session_type = detect_desktop_env_from_processes()
    except Exception:
        session_type = ""

    try:
        u, display, dbus = get_display_and_dbus_env()
    except Exception:
        u, display, dbus = (None, None, None)

    if not u:
        try:
            u = get_logged_in_user()
        except Exception:
            u = None

    return u, display, dbus, session_type


def check_screensaver_timeout(minutes: int):
    """
    GNOME screensaver timeout ayarı belirtilen süreye eşit mi kontrol eder.
    """
    try:
        saniye = minutes * 60
        success, output = run_command([
            "gsettings", "get", "org.gnome.desktop.session", "idle-delay"
        ])

        if not success:
            logger.error(f"[CHECK] idle-delay okunamadı: {output}")
            return False, f"Kontrol başarısız: {output}"

        current = int(output.strip())
        if current == saniye:
            logger.info(f"[CHECK] Screensaver timeout {minutes} dk olarak uyumlu.")
            return True, f"Screensaver timeout {minutes} dk olarak ayarlı."
        else:
            logger.warning(f"[CHECK] Farklı değer: {current // 60} dk.")
            return False, f"Şu anki timeout {current // 60} dk."
    except Exception as e:
        logger.error(f"[CHECK] Hata: {str(e)}")
        return False, f"Kontrol hatası: {str(e)}"


def apply_screensaver_timeout(username=None, param=None):
    """
    GNOME ekran koruyucu timeout değerini uygular.
    Parametre: {"minute": "10"}
    """
    try:
        
        dakika_raw = None
        if isinstance(param, dict):
            dakika_raw = param.get("minute")
        elif isinstance(param, str):
            try:
                p = json.loads(param)
                dakika_raw = p.get("minute")
            except Exception:
                logger.error("[APPLY] Parametre ayrıştırılamadı.")
                return False, "Parametre ayrıştırılamadı."

        if not dakika_raw or not str(dakika_raw).isdigit():
            logger.error("[APPLY] 'minute' parametresi sayısal olmalı.")
            return False, "'minute' parametresi sayısal olmalı."

        dakika = int(dakika_raw)
        saniye = dakika * 60

        # önce ortam bilgileri
        user = get_logged_in_user()
        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()

        if not user or not display or not dbus:
            logger.error("[APPLY] Ortam değişkenleri alınamadı.")
            return False, "Ortam değişkenleri alınamadı."

        if "gnome" not in session_type:
            logger.warning(f"[APPLY] Yalnızca GNOME destekleniyor. Algılanan: {session_type}")
            return False, f"Bu politika yalnızca GNOME için geçerlidir. Algılanan: {session_type}"

        ok, msg = check_screensaver_timeout(dakika)
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        env_prefix = f"DISPLAY={display} DBUS_SESSION_BUS_ADDRESS={dbus}"
        commands = [
            f"{env_prefix} gsettings set org.gnome.desktop.session idle-delay {saniye}",
            f"{env_prefix} gsettings set org.gnome.desktop.screensaver lock-delay 5",
            f"{env_prefix} gsettings set org.gnome.desktop.screensaver lock-enabled true",
            f"{env_prefix} gsettings set org.gnome.desktop.screensaver picture-uri 'file:///opt/screensaver.jpg'",
            f"{env_prefix} gsettings set org.gnome.desktop.screensaver picture-options 'scaled'",
        ]

        for cmd in commands:
            success, output = run_command(["sudo", "-u", user, "bash", "-c", cmd])
            if not success:
                logger.error(f"[APPLY] Komut başarısız: {cmd} -> {output}")
                return False, f"Komut başarısız: {output}"

        logger.info(f"[APPLY] Screensaver timeout {dakika} dk olarak ayarlandı.")
        return True, f"{dakika} dakika sonra ekran koruyucu etkin olacak. Görsel ayarlandı."
    except Exception as e:
        logger.error(f"[APPLY] Hata: {str(e)}")
        return False, f"Apply hatası: {str(e)}"



def check_auto_lock_screen(minutes: int):
    """
    Otomatik ekran kilidi verilen süreye ayarlı mı kontrol eder.
    GNOME: idle-delay
    XFCE : blank-on-ac
    """
    try:
        saniye = minutes * 60
        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()
        if not user or not display or not dbus:
            logger.error("[CHECK] Ortam değişkenleri alınamadı.")
            return False, "Ortam değişkenleri alınamadı."

        env = os.environ.copy()
        env["DISPLAY"] = display
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus

        if "gnome" in session_type:
            success, output = run_command(
                ["sudo", "-u", user, "gsettings", "get", "org.gnome.desktop.session", "idle-delay"],
                env=env
            )
            if not success:
                logger.error(f"[CHECK] idle-delay okunamadı: {output}")
                return False, f"Kontrol başarısız: {output}"

            current_val = int(output.strip().split()[-1])
            if current_val == saniye:
                logger.info(f"[CHECK] GNOME idle-delay {minutes} dk uyumlu.")
                return True, f"GNOME idle-delay {minutes} dk uyumlu."
            else:
                logger.warning(f"[CHECK] GNOME idle-delay {current_val // 60} dk, beklenen {minutes} dk.")
                return False, f"Beklenen {minutes} dk, mevcut {current_val // 60} dk."

        elif "xfce" in session_type:
            success, output = run_command([
                "sudo", "-u", user, "xfconf-query", "-c", "xfce4-power-manager", "-p",
                "/xfce4-power-manager/blank-on-ac"
            ], env=env)
            if not success:
                logger.error(f"[CHECK] XFCE değeri okunamadı: {output}")
                return False, f"Kontrol başarısız: {output}"

            current_val = int(output.strip())
            if current_val == minutes:
                logger.info(f"[CHECK] XFCE blank-on-ac {minutes} dk uyumlu.")
                return True, f"XFCE blank-on-ac {minutes} dk uyumlu."
            else:
                logger.warning(f"[CHECK] XFCE blank-on-ac {current_val} dk, beklenen {minutes} dk.")
                return False, f"Beklenen {minutes} dk, mevcut {current_val} dk."

        else:
            logger.warning(f"[CHECK] Desteklenmeyen masaüstü: {session_type}")
            return False, f"Desteklenmeyen masaüstü: {session_type}"

    except Exception as e:
        logger.error(f"[CHECK] Hata: {str(e)}")
        return False, f"Kontrol hatası: {str(e)}"



def apply_auto_lock_screen(username=None, param=None):
    """
    GNOME ve XFCE için otomatik ekran kilidi uygular.
    Parametre: {"minute": "10"} (dakika cinsinden)
    """
    try:
        dakika = None
        if isinstance(param, dict):
            dakika = param.get("minute")
        elif isinstance(param, str):
            try:
                p = json.loads(param)
                dakika = p.get("minute")
            except Exception:
                logger.error("[APPLY] Parametre ayrıştırılamadı.")
                return False, "Parametre ayrıştırılamadı."

        if not dakika or not str(dakika).isdigit():
            logger.error("[APPLY] 'minute' parametresi sayısal değil.")
            return False, "'minute' parametresi geçersiz."

        dakika = int(dakika)
        saniye = dakika * 60

        ok, msg = check_auto_lock_screen(dakika)
        if ok:
            return True, f"Zaten uyumlu: {msg}"

        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()
        if not user or not display or not dbus:
            logger.error("[APPLY] Ortam değişkenleri alınamadı.")
            return False, "Ortam değişkenleri alınamadı."

        env_prefix = f"DISPLAY={display} DBUS_SESSION_BUS_ADDRESS={dbus}"

        if "gnome" in session_type:
            commands = [
                f"{env_prefix} gsettings set org.gnome.desktop.session idle-delay {saniye}",
                f"{env_prefix} gsettings set org.gnome.desktop.screensaver lock-delay 5",
                f"{env_prefix} gsettings set org.gnome.desktop.screensaver lock-enabled true",
            ]
        elif "xfce" in session_type:
            commands = [
                f"{env_prefix} xfconf-query -c xfce4-session -p /general/LockCommand -s 'xflock4'",
                f"{env_prefix} xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled -s true",
                f"{env_prefix} xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s {dakika}",
            ]
        else:
            logger.warning(f"[APPLY] Desteklenmeyen masaüstü: {session_type}")
            return False, f"Desteklenmeyen masaüstü: {session_type}"

        for cmd in commands:
            success, output = run_command(["sudo", "-u", user, "bash", "-c", cmd])
            if not success:
                logger.error(f"[APPLY] Komut başarısız: {cmd} -> {output}")
                return False, f"Komut başarısız: {output}"

        logger.info(f"[APPLY] {dakika} dakika sonra otomatik ekran kilidi etkinleştirildi.")
        return True, f"{dakika} dakika sonra otomatik ekran kilidi etkinleştirildi."
    except Exception as e:
        logger.error(f"[APPLY] Hata: {str(e)}")
        return False, f"Apply hatası: {str(e)}"


def check_gnome_wallpaper_lockdown(param_data: dict) -> bool:
    try:
        image_path = param_data.get("path")
        if not image_path or not os.path.exists(image_path):
            return False

        abs_path = os.path.abspath(image_path).replace(os.sep, '/')
        expected_uri = f"file://{abs_path}"

        settings_file = "/etc/dconf/db/local.d/00-background-settings"
        if not os.path.exists(settings_file):
            return False

        with open(settings_file, "r") as f:
            content = f.read()

        if f"picture-uri='{expected_uri}'" not in content:
            return False
        if f"picture-uri-dark='{expected_uri}'" not in content:
            return False

        lock_file = "/etc/dconf/db/local.d/locks/background-lock"
        required_locks = [
            "/org/gnome/desktop/background/picture-uri",
            "/org/gnome/desktop/background/picture-uri-dark",
            "/org/gnome/desktop/background/picture-options",
            "/org/gnome/desktop/background/picture-options-dark",
            "/org/gnome/desktop/background/primary-color",
            "/org/gnome/desktop/background/primary-color-dark",
            "/org/gnome/desktop/background/secondary-color",
            "/org/gnome/desktop/background/secondary-color-dark",
        ]

        if not os.path.exists(lock_file):
            return False

        with open(lock_file, "r") as f:
            lock_lines = f.read().splitlines()

        for lock in required_locks:
            if lock not in lock_lines:
                return False

        return True
    except Exception as e:
        logger.error(f"[check_gnome_wallpaper_lockdown] Hata: {e}")
        return False


def apply_gnome_wallpaper_lockdown(username=None, param=None):
    """
    GNOME masaüstü için duvar kağıdını hem aydınlık hem de karanlık modda
    belirtilen resimle kilitler.
    """
    try:
        if not param:
            return False, "Parametre eksik."

        if isinstance(param, str):
            try:
                param_data = json.loads(param)
            except json.JSONDecodeError:
                return False, "Geçersiz JSON formatı."
        elif isinstance(param, dict):
            param_data = param
        else:
            return False, "Parametre tipi hatalı."

        image_path = param_data.get("path")
        if not image_path:
            return False, "'path' parametresi eksik."

        if not os.path.exists(image_path):
            return False, f"Belirtilen resim dosyası bulunamadı: {image_path}"

        abs_path = os.path.abspath(image_path)
        file_uri = f"file://{abs_path.replace(os.sep, '/')}"

        if check_gnome_wallpaper_lockdown(param_data):
            return False, f"GNOME duvar kağıdı zaten bu resimle kilitlenmiş: {abs_path}"

        logger.info(f"[apply_gnome_wallpaper_lockdown] Duvar kağıdı için kullanılacak URI: {file_uri}")

        # Gerekli dizinler
        dirs_to_create = [
            "/etc/dconf/profile",
            "/etc/dconf/db/local.d",
            "/etc/dconf/db/local.d/locks",
        ]
        for d in dirs_to_create:
            run_command(["sudo", "mkdir", "-p", d])

        # Profil dosyası
        profile_path = "/etc/dconf/profile/user"
        profile_content = "user-db:user\nsystem-db:local\n"
        run_command(["sudo", "bash", "-c", f"echo \"{profile_content}\" | tee {profile_path}"])

        # Ayar dosyası
        settings_path = "/etc/dconf/db/local.d/00-background-settings"
        settings_content = f"""[org/gnome/desktop/background]
picture-uri='{file_uri}'
picture-uri-dark='{file_uri}'
picture-options='zoom' 
picture-options-dark='zoom'
primary-color='rgb(0,0,0)'
primary-color-dark='rgb(0,0,0)'
secondary-color='rgb(0,0,0)'
secondary-color-dark='rgb(0,0,0)'
"""
        run_command(["sudo", "bash", "-c", f"echo \"{settings_content}\" | tee {settings_path}"])

        # Lock dosyası
        lock_path = "/etc/dconf/db/local.d/locks/background-lock"
        lock_content = """/org/gnome/desktop/background/picture-uri
/org/gnome/desktop/background/picture-uri-dark
/org/gnome/desktop/background/picture-options
/org/gnome/desktop/background/picture-options-dark
/org/gnome/desktop/background/primary-color
/org/gnome/desktop/background/primary-color-dark
/org/gnome/desktop/background/secondary-color
/org/gnome/desktop/background/secondary-color-dark
"""
        run_command(["sudo", "bash", "-c", f"echo \"{lock_content}\" | tee {lock_path}"])

        # dconf update
        run_command(["sudo", "dconf", "update"])

        return True, f"GNOME duvar kağıdı başarıyla kilitlendi: {abs_path}"

    except Exception as e:
        logger.error(f"[apply_gnome_wallpaper_lockdown] Hata: {e}")
        return False, f"Politika hatası: {str(e)}"




def check_gnome_desktop_icon_policy(param):
    """
    Masaüstü simgeleri politikası daha önce uygulanmış mı kontrol eder.
    """
    try:
        if isinstance(param, str):
            param = json.loads(param)
        elif not isinstance(param, dict):
            return False

        show_trash = param.get("show_trash", True)
        show_home = param.get("show_home", True)

        settings_path = "/etc/dconf/db/local.d/00-desktop-icons-policy"
        if not os.path.isfile(settings_path):
            return False

        expected_content = f"""[org/gnome/shell/extensions/ding]
show-trash={str(show_trash).lower()}
show-home={str(show_home).lower()}
"""
        with open(settings_path, "r") as f:
            content = f.read().strip()

        return content == expected_content.strip()

    except Exception as e:
        logger.error(f"[check_gnome_desktop_icon_policy] Hata: {e}")
        return False


def apply_gnome_desktop_icon_policy(username=None, param=None):
    """
    GNOME masaüstündeki "Çöp" ve "Ev" simgelerinin görünürlüğünü merkezi olarak yönetir.
    Root yetkisi gereklidir.
    """
    try:
        # Parametre ayrıştırma
        if isinstance(param, str):
            param = json.loads(param)
        elif not isinstance(param, dict):
            return False, "Parametre JSON sözlük veya string olmalı."

        show_trash = param.get("show_trash", True)
        show_home = param.get("show_home", True)

        if check_gnome_desktop_icon_policy(param):
            return False, "Masaüstü simgeleri politikası zaten uygulanmış."

        show_trash_str = str(show_trash).lower()
        show_home_str = str(show_home).lower()

        # Gerekli dizinler
        dirs_to_create = [
            "/etc/dconf/profile",
            "/etc/dconf/db/local.d",
            "/etc/dconf/db/local.d/locks"
        ]
        for d in dirs_to_create:
            run_command(["sudo", "mkdir", "-p", d])

        # Profil dosyası
        profile_path = "/etc/dconf/profile/user"
        profile_content = "user-db:user\nsystem-db:local\n"
        run_command(["sudo", "bash", "-c", f"echo '{profile_content}' | tee {profile_path}"])

        # Ayar dosyası
        settings_path = "/etc/dconf/db/local.d/00-desktop-icons-policy"
        settings_content = f"""[org/gnome/shell/extensions/ding]
show-trash={show_trash_str}
show-home={show_home_str}
"""
        run_command(["sudo", "bash", "-c", f"echo '{settings_content}' | tee {settings_path}"])

        # Lock dosyası
        lock_path = "/etc/dconf/db/local.d/locks/desktop-icons-lock"
        lock_content = """/org/gnome/shell/extensions/ding/show-trash
/org/gnome/shell/extensions/ding/show-home
"""
        run_command(["sudo", "bash", "-c", f"echo '{lock_content}' | tee {lock_path}"])

        # dconf update
        run_command(["sudo", "dconf", "update"])

        return True, f"Masaüstü simgeleri politikası uygulandı: Çöp={show_trash_str}, Ev={show_home_str}"

    except Exception as e:
        logger.error(f"[apply_gnome_desktop_icon_policy] Hata: {e}")
        return False, f"Politika hatası: {str(e)}"



