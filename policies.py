import json
import subprocess
from utils import get_logged_in_user, get_desktop_env

def auto_lock_screen(username, param):
    try:
        time_mins = int(param.get("time", 0))
        time_seconds = time_mins * 60

        if time_seconds <= 0:
            return False, "Geçersiz süre. Lütfen 0'dan büyük bir değer girin."

        if check_auto_lock_screen(param):
            return False, "Bu ekran kilidi ayarı zaten uygulanmış."

        session_type = get_desktop_env()
        uid, user, display, dbus = get_logged_in_user()

        if not all([user, display, dbus]):
            return False, "Gerekli ortam değişkenleri (DISPLAY veya DBUS) alınamadı."

        env_prefix = f'DISPLAY={display} DBUS_SESSION_BUS_ADDRESS="{dbus}" '

        commands = []
        if "gnome" in session_type:
            commands = [
                "gsettings set org.gnome.desktop.screensaver lock-enabled true"
                f"gsettings set org.gnome.desktop.screensaver lock-delay {time_seconds}",
            ]
        elif "xfce" in session_type:
            commands = [
                "xfconf-query -c xfce4-session -p /general/LockCommand -s 'xflock4'",
                "xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled -s true",
                f"xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s {time_mins}",
                f"xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-battery -s {time_mins}",
                "xfconf-query -c xfce4-session -p /shutdown/LockScreen -s true"
            ]
        else:
            return False, f"Desteklenmeyen masaüstü ortamı: {session_type}"
 
        # Komutları çalıştır
        for cmd in commands:
            subprocess.run(
                ["sudo", "-u", user, "bash", "-c", env_prefix + cmd],
                check=True
            )

        return True, f"{dakika} dakika sonra otomatik ekran kilidi etkinleştirildi."

    except Exception as e:
        return False, f"Politika hatası: {e}"

def password_expiration_interval(username, param):
    try:
        max_days = param.get("max_days","99999")
        warning_before = param.get("warning_before","14")
        subprocess.run(["chage", "-M", str(max_days), "-W", str(warning_before), str(username)], check=True)
        return True, f"{username} için parola süresi {max_days} gün olarak ayarlandı."
    except Exception as e:
        return False, f"Hata: {str(e)}"