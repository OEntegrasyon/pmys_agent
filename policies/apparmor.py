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
        success, output = run_command(['systemctl', 'is-active', 'apparmor'])
        if success and output == "active":
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

    # Önce apt depolarını güncelle
    success, output = run_command(['sudo', 'apt-get', 'update'])
    if not success:
        return False, f"apt-get update başarısız oldu: {output}"
        
    # Eksik paketleri kur
    success, output = run_command(['sudo', 'apt-get', 'install', '-y'] + required_packages)
    if not success:
        return False, f"AppArmor paketleri kurulamadı: {output}"
    # Servisi etkinleştir (enable) ve hemen başlat (start)
    success, output = run_command(['sudo', 'systemctl', 'enable', '--now', 'apparmor'])
    if not success:
        return False, f"AppArmor servisi etkinleştirilemedi: {output}"

    return True, "AppArmor paketleri başarıyla kuruldu ve servis etkinleştirildi."

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
        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"GRUB yapılandırma dosyası güncellenemedi: {output}"
        # GRUB'u güncelle! Bu adım kritik.
        success, output = run_command(['sudo', 'update-grub'])
        if not success:
            return False, f"GRUB güncellenirken hata: {output}"

        return True, "AppArmor, GRUB yapılandırmasında başarıyla etkinleştirildi. Değişikliklerin geçerli olması için yeniden başlatma gerekir."
    except subprocess.CalledProcessError as e:
        return False, f"GRUB güncellenirken hata: {e}. sudoers dosyasını kontrol edin."


# ------------------------------------------------------------------------------
# Politika 3: Tüm AppArmor Profillerini Enforce veya Complain Modunda oldupundan emin ol
def _parse_apparmor_status(output):
    """
    'apparmor_status' komutunun çıktısını analiz eder ve iki önemli
    değeri (disabled_count, unconfined_count) döndürür.
    """
    disabled_count = 0
    unconfined_count = 0
    
    # "X profiles are disabled." (X profil devre dışı) satırını bul
    disabled_match = re.search(r"^\s*(\d+)\s+profiles\s+are\s+disabled", output, re.MULTILINE)
    if disabled_match:
        disabled_count = int(disabled_match.group(1))

    # "X processes are unconfined..." (X süreç korumasız) satırını bul
    unconfined_match = re.search(r"^\s*(\d+)\s+processes\s+are\s+unconfined", output, re.MULTILINE)
    if unconfined_match:
        unconfined_count = int(unconfined_match.group(1))
        
    return disabled_count, unconfined_count

def ensure_no_apparmor_profiles_are_disabled(username, parameters):
    """
    CIS 1.3.1.3 DENETİM (AUDIT) FONKSİYONU - SADECE RAPORLAMA.
    'apparmor_status' komutunu çalıştırır ve hem devre dışı (disabled) profilleri
    hem de korumasız (unconfined) çalışan süreçleri denetler.
    
    'apply' (düzeltme) fonksiyonunu ASLA çağırmaz, sadece rapor (mesaj) döner.
    """
    
    try:
        # CIS Audit komutunu çalıştır.
        success, output = run_command(['sudo', 'apparmor_status'])
        
        if not success:
            return False, f"'apparmor_status' komutu çalıştırılamadı. AppArmor yüklü mü? Hata: {output}"

        disabled_count, unconfined_count = _parse_apparmor_status(output)

        # 1. Kontrol: Devre dışı (disabled) profil var mı?
        if disabled_count > 0:
            return False, f"Uyumsuz: Sistemde {disabled_count} adet 'disabled' (devre dışı) AppArmor profili bulundu."

        # 2. Kontrol: Korumasız (unconfined) süreç var mı?
        if unconfined_count > 0:
            return False, f"Uyumsuz: Sistemde {unconfined_count} adet 'unconfined' (korumasız) çalışan süreç bulundu."
            
        # Eğer her iki kontrol de 0 (sıfır) ise, sistem uyumludur.
        return True, "Tüm AppArmor profilleri yüklü ve çalışan süreçler koruma altında (enforce/complain modunda)."

    except Exception as e:
        return False, f"AppArmor denetimi sırasında genel hata: {e}"


# ------------------------------------------------------------------------------
# Politika 4: Tüm AppArmor Profillerini 'enforce' Moduna Al

def _parse_apparmor_status_level2(output):
    """
    'apparmor_status' çıktısını CIS 1.3.1.4 (Level 2) için analiz eder.
    'enforce' (sıkı) modda olmayan TÜM profillerin ve süreçlerin
    (complain, disabled, unconfined) toplam sayısını döndürür.
    """
    non_enforced_count = 0
    
    # 1. 'complain' modundaki profiller (Uyumsuz)
    complain_profiles_match = re.search(r"^\s*(\d+)\s+profiles\s+are\s+in\s+complain\s+mode", output, re.MULTILINE)
    if complain_profiles_match:
        non_enforced_count += int(complain_profiles_match.group(1))

    # 2. 'disabled' (devre dışı) profiller (Uyumsuz)
    disabled_profiles_match = re.search(r"^\s*(\d+)\s+profiles\s+are\s+disabled", output, re.MULTILINE)
    if disabled_profiles_match:
        non_enforced_count += int(disabled_profiles_match.group(1))
        
    # 3. 'complain' modundaki süreçler (Uyumsuz)
    complain_processes_match = re.search(r"^\s*(\d+)\s+processes\s+are\s+in\s+complain\s+mode", output, re.MULTILINE)
    if complain_processes_match:
        non_enforced_count += int(complain_processes_match.group(1))

    # 4. 'unconfined' (korumasız) süreçler (Kritik - Uyumsuz)
    unconfined_processes_match = re.search(r"^\s*(\d+)\s+processes\s+are\s+unconfined", output, re.MULTILINE)
    if unconfined_processes_match:
        non_enforced_count += int(unconfined_processes_match.group(1))

    return non_enforced_count

def set_apparmor_profiles_to_enforce(username, parameters):
    """
    CIS 1.3.1.4 DENETİM (AUDIT) FONKSİYONU (Level 2).
    'apparmor_status' komutunu çalıştırır ve 'complain', 'disabled', 
    veya 'unconfined' modda olan TÜM profil/süreçleri denetler.
    
    Uyumsuzluk bulursa, 'apply' fonksiyonunu çağırır.
    """
    
    try:
        # CIS Audit komutunu çalıştır.
        success, output = run_command(['sudo', 'apparmor_status'])
        
        if not success:
            return False, f"'apparmor_status' komutu çalıştırılamadı. AppArmor yüklü mü? Hata: {output}"

        # Çıktıyı analiz et
        non_enforced_count = _parse_apparmor_status_level2(output)

        if non_enforced_count == 0:
            # Sıfır ise, her şey 'enforce' modundadır.
            return True, "Tüm AppArmor profilleri ve süreçleri 'enforce' (sıkı) modda."
        else:
            # Sıfırdan büyükse, uyumsuzluk var demektir.
            print(f"Denetim: {non_enforced_count} adet 'enforce' modunda olmayan profil/süreç bulundu. Düzeltme uygulanacak.")
            return apply_enforce_all_profiles(username, parameters)

    except Exception as e:
        return False, f"AppArmor (Level 2) denetimi sırasında genel hata: {e}"

def apply_enforce_all_profiles(username, parameters):
    """
    CIS 1.3.1.4 
    Tüm AppArmor profillerini 'enforce' (Sıkı Mod) moduna alır.
    """
    
    # CIS 1.3.1.4 tarafından önerilen tek Düzeltme komutu
    enforce_cmd = ['sudo', 'aa-enforce', '/etc/apparmor.d/*']
    
    # Değişiklikleri etkinleştirmek için 'reload' komutunu da çalıştırmak
    reload_cmd = ['sudo', 'service', 'apparmor', 'reload']

    try:
        print("AppArmor Düzeltme: Tüm profiller 'enforce' (sıkı) moda alınıyor...")
        success, output = run_command(enforce_cmd)
        
        if not success:
            return False, f"'aa-enforce /etc/apparmor.d/*' komutu çalıştırılırken hata: {output}"

        print("AppArmor Düzeltme: Profil değişiklikleri 'reload' ile yeniden yükleniyor...")
        success, output = run_command(reload_cmd)

        if not success:
             return False, f"AppArmor servisi 'reload' edilirken hata: {output}"

        return True, "Tüm AppArmor profilleri 'enforce' moduna alındı ve servis yeniden yüklendi. NOT: Tam koruma için, uygulamaların yeniden başlatılması gerekebilir."

    except Exception as e:
        return False, f"AppArmor profilleri (Level 2) uygulanırken genel hata: {e}"