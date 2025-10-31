import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
import stat

# ==============================================================================
# == BOOTLOADER (ÖNYÜKLEYİCİ) GÜVENLİĞİ POLİTİKALARI ===========================
# ==============================================================================

# Politika 1: Bootloader Parolasını Zorunlu Kıl
def enforce_bootloader_password(username, parameters):
    """
    GRUB önyükleyicisine parola koruması eklenip eklenmediğini kontrol eder.
    Eğer parola yoksa, parametrelerde belirtilen kullanıcı ve parola özeti (hash)
    ile yeni bir yapılandırma dosyası oluşturur.
    """
    grub_cfg_path = "/boot/grub/grub.cfg"
    
    try:
        if not os.path.exists(grub_cfg_path):
            return False, f"{grub_cfg_path} bulunamadı."

        with open(grub_cfg_path, "r") as f:
            content = f.read()

        # grub.cfg içinde parola ayarlanmış mı diye kontrol et
        if "password_pbkdf2" in content and "set superusers" in content:
            return True, "GRUB parolası zaten ayarlanmış görünüyor."
        else:
            return apply_bootloader_password(parameters)

    except Exception as e:
        return False, f"Bootloader parola kontrolünde hata: {e}"

def apply_bootloader_password(parameters):
    """
    Parametrelerde verilen kullanıcı adı ve parola özeti (hash) ile
    /etc/grub.d/ içinde yeni bir yetkilendirme dosyası oluşturur ve GRUB'u günceller.
    """
    grub_user = parameters.get("grub_user")
    password_hash = parameters.get("password_hash")

    if not grub_user or not password_hash:
        return False, "Politika hatası: 'grub_user' ve 'password_hash' parametreleri zorunludur."
    
    # GRUB parola hash'inin doğru formatta olup olmadığını basitçe kontrol edelim
    if not password_hash.startswith("grub.pbkdf2.sha512."):
        return False, "Politika hatası: 'password_hash' geçerli bir GRUB PBKDF2 özeti değil."

    auth_file_path = "/etc/grub.d/01_security"
    temp_path = "/tmp/01_security.new"
    
    # Yetkilendirme dosyasının içeriğini oluştur
    content = f"""
#!/bin/sh
cat <<EOF
set superusers="{grub_user}"
password_pbkdf2 {grub_user} {password_hash}
EOF
"""
    try:
        with open(temp_path, "w") as f:
            f.write(content)
        
        # Dosyayı sudo ile taşı
        success, output = run_command(['sudo', 'mv', temp_path, auth_file_path])
        if not success:
            return False, f"Yetkilendirme dosyası oluşturulamadı: {output}"
        # Dosyayı çalıştırılabilir yap
        success, output = run_command(['sudo', 'chmod', '+x', auth_file_path])
        if not success:
            return False, f"Yetkilendirme dosyası çalıştırılabilir yapılamadı: {output}"
        
        linux_config_path = "/etc/grub.d/10_linux"
        sed_cmd = [
            'sudo', 'sed', '-i',
            '/CLASS=.*--unrestricted.*/!s/CLASS="\\(.*\\)"/CLASS="\\1 --unrestricted"/',
            linux_config_path
        ]
        print(f"GRUB: {linux_config_path} dosyasına --unrestricted bayrağı ekleniyor...")
        success, output = run_command(sed_cmd)
        if not success:
            return False, f"--unrestricted bayrağı {linux_config_path} dosyasına eklenirken hata: {output}"
        # GRUB'u güncelle
        success, output = run_command(['sudo', 'update-grub'])
        if not success:
            return False, f"GRUB güncellenemedi: {output}"

        return True, "GRUB parolası başarıyla ayarlandı ve GRUB güncellendi. Yeniden başlatma sonrası aktif olacaktır."

    except subprocess.CalledProcessError as e:
        return False, f"sudo veya GRUB komutlarında hata: {e}. 'sudoers' dosyasını kontrol edin."
    except Exception as e:
        return False, f"Bootloader parolası uygulanırken hata: {e}"

# --------------------------------------------------------------------------------

#  Bootloader Yapılandırma İzinlerini Sıkılaştır
def harden_bootloader_permissions(username, parameters):
    """
    grub.cfg dosyasının sahibinin root:root ve izinlerinin 600 (rw-------) olmasını sağlar.
    """
    # Bu politika parametre gerektirmez.
    try:
        grub_cfg_path = _find_grub_cfg_path()
        if not grub_cfg_path:
            return False, "grub.cfg dosyası /boot/grub/ veya /boot/grub2/ içinde bulunamadı."

        file_stat = os.stat(grub_cfg_path)
        current_perms = stat.S_IMODE(file_stat.st_mode)
        current_uid = file_stat.st_uid
        current_gid = file_stat.st_gid

        # İstenen durum: sahip=root(0), grup=root(0), izinler=600 (octal 0o600)
        is_secure = (current_uid == 0 and current_gid == 0 and current_perms == 0o600)

        if is_secure:
            return True, f"grub.cfg dosya izinleri ({oct(current_perms)[2:]} root:root) zaten güvenli."
        else:
            return apply_bootloader_permissions(grub_cfg_path)

    except Exception as e:
        return False, f"Bootloader izinleri kontrol edilirken hata: {e}"

def apply_bootloader_permissions(path: str):
    """
    Belirtilen dosyanın sahibini root:root ve izinlerini 600 olarak ayarlar.
    """
    try:
        # Sahibi root:root yap
        success, output = run_command(['sudo', 'chown', 'root:root', path])
        if not success:
            return False, f"Dosya sahibi değiştirilemedi: {output}"
        # İzinleri 600 (sadece root okur/yazar) yap
        success, output = run_command(['sudo', 'chmod', '600', path])
        if not success:
            return False, f"Dosya izinleri değiştirilemedi: {output}"
        return True, f"{path} dosyasının sahibi root:root ve izinleri 600 olarak ayarlandı."
    except Exception as e:
        return False, f"Bootloader izinleri uygulanırken hata: {e}"

def _find_grub_cfg_path():
    """grub.cfg dosyasının yaygın konumlarını arar."""
    common_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    for path in common_paths:
        if os.path.exists(path):
            return path
    return None

    