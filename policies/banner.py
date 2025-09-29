import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
import stat
# ==============================================================================
# == GİRİŞ BAŞLIKLARI (LOGIN BANNERS) POLİTİKALARI (YENİ İSİMLERLE) ==============
# ==============================================================================

### Politika 1: Günün Mesajını Yapılandır (/etc/motd) ###

def configure_message_of_the_day(username, parameters):
    """
    /etc/motd dosyasının içeriğini, sahibini ve izinlerini kontrol eder.
    """
    banner_text = parameters.get("banner_text")
    if not banner_text:
        return False, "Politika hatası: 'banner_text' parametresi zorunludur."

    file_path = "/etc/motd"
    try:
        # Dosyanın mevcut durumunu kontrol et
        if os.path.exists(file_path):
            with open(file_path, "r") as f: content_ok = banner_text in f.read()
            file_stat = os.stat(file_path)
            owner_ok = file_stat.st_uid == 0 and file_stat.st_gid == 0
            perms_ok = stat.S_IMODE(file_stat.st_mode) == 0o644
            if content_ok and owner_ok and perms_ok:
                return True, "Günün Mesajı (motd) zaten doğru yapılandırılmış."
        
        # Durum doğru değilse veya dosya hiç yoksa, uygula
        return apply_message_of_the_day(parameters)
    except Exception as e:
        return False, f"Günün Mesajı (motd) kontrol edilirken hata: {e}"

def apply_message_of_the_day(parameters):
    """
    /etc/motd dosyasını oluşturur/günceller ve izinlerini ayarlar.
    """
    banner_text = parameters.get("banner_text")
    file_path = "/etc/motd"
    temp_path = "/tmp/motd.tmp"
    try:
        with open(temp_path, "w") as f: f.write(banner_text + "\n")
        success, output=run_command(['sudo', 'mv', temp_path, file_path])
        if not success:
            return False, f"Günün Mesajı (motd) dosyası güncellenemedi: {output}"
        success, output = run_command(['sudo', 'chown', 'root:root', file_path])
        if not success:
            return False, f"Günün Mesajı (motd) dosyasının sahibi değiştirilemedi: {output}"
        success, output = run_command(['sudo', 'chmod', '644', file_path])
        if not success:
            return False, f"Günün Mesajı (motd) dosyasının izinleri değiştirilemedi: {output}"
        return True, "Günün Mesajı (motd) başarıyla yapılandırıldı."
    except Exception as e:
        return False, f"Günün Mesajı (motd) uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."

# ------------------------------------------------------------------------------

### Politika 2: Yerel Giriş Uyarısını Yapılandır (/etc/issue) ###

def configure_local_login_banner(username, parameters):
    """
    /etc/issue dosyasının içeriğini, sahibini ve izinlerini kontrol eder.
    """
    banner_text = parameters.get("banner_text")
    if not banner_text:
        return False, "Politika hatası: 'banner_text' parametresi zorunludur."

    file_path = "/etc/issue"
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f: content_ok = banner_text in f.read()
            file_stat = os.stat(file_path)
            owner_ok = file_stat.st_uid == 0 and file_stat.st_gid == 0
            perms_ok = stat.S_IMODE(file_stat.st_mode) == 0o644
            if content_ok and owner_ok and perms_ok:
                return True, "Yerel giriş uyarı başlığı (issue) zaten doğru yapılandırılmış."
        
        return apply_local_login_banner(parameters)
    except Exception as e:
        return False, f"Yerel giriş uyarı başlığı (issue) kontrol edilirken hata: {e}"

def apply_local_login_banner(parameters):
    """
    /etc/issue dosyasını oluşturur/günceller ve izinlerini ayarlar.
    """
    banner_text = parameters.get("banner_text")
    file_path = "/etc/issue"
    temp_path = "/tmp/issue.tmp"
    try:
        with open(temp_path, "w") as f: f.write(banner_text + "\n")
        success, output = run_command(['sudo', 'mv', temp_path, file_path])
        if not success:
            return False, f"Yerel giriş uyarı başlığı (issue) dosyası güncellenemedi: {output}"
        success, output = run_command(['sudo', 'chown', 'root:root', file_path])
        if not success:
            return False, f"Yerel giriş uyarı başlığı (issue) dosyasının sahibi değiştirilemedi: {output}"
        success, output = run_command(['sudo', 'chmod', '644', file_path])
        if not success:
            return False, f"Yerel giriş uyarı başlığı (issue) dosyasının izinleri değiştirilemedi: {output}"
        return True, "Yerel giriş uyarı başlığı (issue) başarıyla yapılandırıldı."
    except Exception as e:
        return False, f"Yerel giriş uyarı başlığı (issue) uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."

# ------------------------------------------------------------------------------

### Politika 3: Uzak Giriş Uyarısını Yapılandır (/etc/issue.net) ###

def configure_remote_login_banner(username, parameters):
    """
    /etc/issue.net dosyasının içeriğini, sahibini ve izinlerini kontrol eder.
    """
    banner_text = parameters.get("banner_text")
    if not banner_text:
        return False, "Politika hatası: 'banner_text' parametresi zorunludur."

    file_path = "/etc/issue.net"
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f: content_ok = banner_text in f.read()
            file_stat = os.stat(file_path)
            owner_ok = file_stat.st_uid == 0 and file_stat.st_gid == 0
            perms_ok = stat.S_IMODE(file_stat.st_mode) == 0o644
            if content_ok and owner_ok and perms_ok:
                return True, "Uzak giriş uyarı başlığı (issue.net) zaten doğru yapılandırılmış."
        
        return apply_remote_login_banner(parameters)
    except Exception as e:
        return False, f"Uzak giriş uyarı başlığı (issue.net) kontrol edilirken hata: {e}"

def apply_remote_login_banner(parameters):
    """
    /etc/issue.net dosyasını oluşturur/günceller ve izinlerini ayarlar.
    """
    banner_text = parameters.get("banner_text")
    file_path = "/etc/issue.net"
    temp_path = "/tmp/issue.net.tmp"
    try:
        with open(temp_path, "w") as f: f.write(banner_text + "\n")
        success, output = run_command(['sudo', 'mv', temp_path, file_path])
        if not success:
            return False, f"Uzak giriş uyarı başlığı (issue.net) dosyası güncellenemedi: {output}"
        success, output = run_command(['sudo', 'chown', 'root:root', file_path])
        if not success:
            return False, f"Uzak giriş uyarı başlığı (issue.net) dosyasının sahibi değiştirilemedi: {output}"
        success, output = run_command(['sudo', 'chmod', '644', file_path])
        if not success:
            return False, f"Uzak giriş uyarı başlığı (issue.net) dosyasının izinleri değiştirilemedi: {output}"
        return True, "Uzak giriş uyarı başlığı (issue.net) başarıyla yapılandırıldı."
    except Exception as e:
        return False, f"Uzak giriş uyarı başlığı (issue.net) uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."

