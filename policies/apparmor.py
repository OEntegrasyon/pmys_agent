import os
import re
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command


# ------------------------------------------------------------------------------
# ==============================================================================
# == APPARMOR KURULUM VE PROFİL POLİTİKALARI ====================================
# ==============================================================================
# Politika 1: AppArmor Kurulumunu Doğrula
def ensure_apparmor_is_installed_and_active(username, parameters):
    """
    AppArmor paketlerinin kurulu ve servisin aktif olduğunu kontrol eder.
    Eksikse, kurulum ve aktivasyon yapar.
    """
    # Bu politika parametre gerektirmez.
    required_packages = ["apparmor", "apparmor-utils"]
    
    try:
        # 1. Paketlerin kurulu olup olmadığını kontrol et
        packages_installed = True
        for package in required_packages:
            result = subprocess.run(['dpkg', '-l', package], capture_output=True, text=True, check=False)
            if f"ii  {package}" not in result.stdout:
                packages_installed = False
                break
        
        # 2. Servisin aktif olup olmadığını kontrol et
        service_active = False
        result = subprocess.run(['systemctl', 'is-active', 'apparmor'], capture_output=True, text=True, check=False)
        if result.stdout.strip() == "active":
            service_active = True

        if packages_installed and service_active:
            return True, "AppArmor paketleri kurulu ve servis aktif durumda."
        else:
            # Eksik bir durum varsa, apply fonksiyonunu çağır
            return apply_apparmor_installation_and_activation()
            
    except Exception as e:
        return False, f"AppArmor kurulum/aktivasyon kontrolünde hata: {e}"

def apply_apparmor_installation_and_activation():
    """
    AppArmor paketlerini kurar ve servisi etkinleştirip başlatır.
    """
    required_packages = ["apparmor", "apparmor-utils"]
    try:
        # Önce apt depolarını güncelle
        subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
        # Eksik paketleri kur
        subprocess.run(['sudo', 'apt-get', 'install', '-y'] + required_packages, check=True, capture_output=True)
        
        # Servisi etkinleştir (enable) ve hemen başlat (start)
        subprocess.run(['sudo', 'systemctl', 'enable', '--now', 'apparmor'], check=True)

        return True, "AppArmor paketleri başarıyla kuruldu ve servis etkinleştirildi."
    except subprocess.CalledProcessError as e:
        error_message = e.stderr or e.stdout
        return False, f"AppArmor kurulumu/etkinleştirmesi sırasında hata: {error_message}. sudoers dosyasını kontrol edin."
    except Exception as e:
        return False, f"AppArmor kurulumu/etkinleştirmesi uygulanırken genel hata: {e}"

# ------------------------------------------------------------------------------
# Politika 2: AppArmor'u Önyükleyicide Etkinleştir
def enforce_apparmor_in_bootloader(username, parameters):
    """
    GRUB yapılandırmasında AppArmor'un önyüklemede aktif edilmesini sağlar.
    """
    # Bu politika parametre gerektirmez.
    grub_config_path = "/etc/default/grub"
    
    try:
        if not os.path.exists(grub_config_path):
            return False, f"{grub_config_path} dosyası bulunamadı."

        with open(grub_config_path, "r") as f:
            content = f.read()

        # GRUB_CMDLINE_LINUX içinde gerekli parametreler var mı?
        cmdline_match = re.search(r'GRUB_CMDLINE_LINUX="([^"]*)"', content)
        if not cmdline_match:
            return False, "GRUB_CMDLINE_LINUX satırı bulunamadı."

        current_cmdline = cmdline_match.group(1)
        
        if "apparmor=1" in current_cmdline and "security=apparmor" in current_cmdline:
            return True, "AppArmor, GRUB yapılandırmasında zaten etkin."
        else:
            return apply_apparmor_to_grub(grub_config_path, content, current_cmdline)

    except Exception as e:
        return False, f"GRUB kontrolünde hata: {e}"

def apply_apparmor_to_grub(config_path, current_content, current_cmdline):
    """
    /etc/default/grub dosyasını günceller ve update-grub komutunu çalıştırır.
    """
    try:
        new_cmdline = current_cmdline
        if "apparmor=1" not in new_cmdline:
            new_cmdline += " apparmor=1"
        if "security=apparmor" not in new_cmdline:
            new_cmdline += " security=apparmor"
        
        # Dosya içeriğini yeni cmdline ile değiştir
        new_content = current_content.replace(f'GRUB_CMDLINE_LINUX="{current_cmdline}"', f'GRUB_CMDLINE_LINUX="{new_cmdline.strip()}"')
        
        temp_path = "/tmp/grub.new"
        with open(temp_path, "w") as f:
            f.write(new_content)

        # Değişiklikleri sudo ile uygula
        subprocess.run(['sudo', 'mv', temp_path, config_path], check=True)
        # GRUB'u güncelle! Bu adım kritik.
        subprocess.run(['sudo', 'update-grub'], check=True)

        return True, "AppArmor, GRUB yapılandırmasında başarıyla etkinleştirildi. Değişikliklerin geçerli olması için yeniden başlatma gerekir."
    except subprocess.CalledProcessError as e:
        return False, f"GRUB güncellenirken hata: {e}. sudoers dosyasını kontrol edin."
    except Exception as e:
        return False, f"GRUB yapılandırması uygulanırken hata: {e}"

# ------------------------------------------------------------------------------
# Politika 3: Tüm AppArmor Profillerini Enforce veya Complain Moduna Al
def ensure_no_apparmor_profiles_are_disabled(username, parameters):
    """
    Hiçbir AppArmor profilinin devre dışı bırakılmadığından emin olur.
    /etc/apparmor.d/disable/ dizinini kontrol eder.
    """
    # Bu politika parametre gerektirmez.
    disable_dir = "/etc/apparmor.d/disable/"
    
    try:
        # Devre dışı bırakma dizini yoksa veya boşsa, her şey yolundadır.
        if not os.path.exists(disable_dir) or not os.listdir(disable_dir):
            return True, "Devre dışı bırakılmış AppArmor profili bulunmuyor."
        else:
            # Eğer dizinde dosya varsa, bu profiller devre dışı bırakılmış demektir.
            return apply_reenable_all_profiles()

    except Exception as e:
        return False, f"Devre dışı AppArmor profilleri kontrol edilirken hata: {e}"

def apply_reenable_all_profiles():
    """
    /etc/apparmor.d/disable/ dizinindeki tüm sembolik linkleri silerek
    devre dışı bırakılmış profilleri yeniden etkinleştirir ve AppArmor'u yeniden yükler.
    """
    disable_dir = "/etc/apparmor.d/disable/"
    try:
        disabled_profiles = os.listdir(disable_dir)
        for profile_link in disabled_profiles:
            full_path = os.path.join(disable_dir, profile_link)
            print(f"'{profile_link}' profili yeniden etkinleştiriliyor...")
            subprocess.run(['sudo', 'rm', full_path], check=True)
        
        # AppArmor servisini yeniden yükleyerek değişiklikleri aktif et
        subprocess.run(['sudo', 'service', 'apparmor', 'reload'], check=True)
        
        return True, f"Devre dışı bırakılmış profiller ({', '.join(disabled_profiles)}) başarıyla yeniden etkinleştirildi."

    except subprocess.CalledProcessError as e:
        error_message = e.stderr or e.stdout
        return False, f"Profiller yeniden etkinleştirilirken hata: {error_message}. sudoers dosyasını kontrol edin."
    except Exception as e:
        return False, f"Profiller yeniden etkinleştirilirken genel hata: {e}"
# ------------------------------------------------------------------------------
# Politika 4: Tüm AppArmor Profillerini 'enforce' Moduna Al
def set_apparmor_profiles_to_enforce(username, parameters):
    """
    'complain' (şikayet) modundaki tüm AppArmor profillerini 'enforce' (zorlama) moduna geçirir.
    """
    # Bu politika parametre gerektirmez.
    try:
        # aa-status komutunu sudo ile çalıştır
        status_result = subprocess.run(['sudo', 'aa-status'], capture_output=True, text=True, check=True)
        
        # 'complain mode' içinde profil var mı diye kontrol et
        complain_section = re.search(r'(\d+)\s+profiles are in complain mode.', status_result.stdout)
        
        if complain_section and int(complain_section.group(1)) > 0:
            # Complain modunda profil varsa, apply fonksiyonunu çağır
            return apply_enforce_all_profiles()
        else:
            return True, "Tüm AppArmor profilleri zaten 'enforce' modunda veya hiç 'complain' modunda profil yok."

    except subprocess.CalledProcessError as e:
        return False, f"aa-status komutu çalıştırılamadı: {e.stderr}. sudoers dosyasını kontrol edin."
    except Exception as e:
        return False, f"AppArmor profil durumu kontrol edilirken hata: {e}"

def apply_enforce_all_profiles():
    """
    Tüm profilleri enforce moduna alır.
    """
    try:
        # aa-enforce komutu ile tüm profilleri enforce moduna al
        subprocess.run(['sudo', 'aa-enforce', '/etc/apparmor.d/*'], capture_output=True, text=True, check=True)
        return True, "Tüm 'complain' modundaki profiller başarıyla 'enforce' moduna alındı."
    except subprocess.CalledProcessError as e:
        return False, f"Profiller 'enforce' moduna alınırken hata: {e.stderr}. sudoers dosyasını kontrol edin."
    except Exception as e:
        return False, f"AppArmor profilleri enforce edilirken hata: {e}"
