import os
import subprocess
from datetime import datetime
import logger
from utils import get_logged_in_user, get_desktop_env, run_command

# ==============================================================================
# == GÜVENSİZ PAKETLERİ KALDIRMA POLİTİKASI ===================================
# ==============================================================================

def ensure_package_is_removed(username, parameters):
    """
    Parametre olarak belirtilen bir paketin sistemde kurulu olup olmadığını kontrol eder.
    Eğer paket kurulu ise, 'apply' fonksiyonunu çağırarak paketi kaldırır.
    """
    # Bu politika kullanıcıya özel değil, sistem geneli olduğu için 'username' kullanılmaz.
    
    package_name = parameters.get("package_name")
    if not package_name:
        return False, "Politika hatası: 'package_name' parametresi ile kaldırılacak paket adı belirtilmemiş."
        
    try:
       success, output = run_command(['dpkg', '-l', package_name])

       if f"ii  {package_name}" in output:
            return apply_package_removal(package_name)
       else:
            return True, f"'{package_name}' paketi zaten sistemde kurulu değil."

    except Exception as e:
        return False, f"Paket durumu kontrol edilirken beklenmedik bir hata oluştu: {e}"


def apply_package_removal(package_name: str) -> tuple[bool, str]:
    """
    Belirtilen paketi yapılandırma dosyalarıyla birlikte sistemden kaldırır ('purge').
    sudo yetkisi gerektirir.
    """
    try:
        print(f"'{package_name}' paketi sistemden kaldırılıyor...")
        # '-y' parametresi tüm onay sorularına otomatik 'evet' yanıtı verir.
        # 'purge' komutu, paketi ve ilgili tüm yapılandırma dosyalarını siler.
        success, output = run_command(
            ['sudo', 'apt-get', 'purge', '-y', package_name]
        )
        if not success:
            return False, f"'{package_name}' paketi kaldırılamadı: {output}. 'sudoers' dosyasını kontrol edin."
        return True, f"'{package_name}' paketi ve yapılandırma dosyaları başarıyla sistemden kaldırıldı."
    except Exception as e:
        return False, f"Paket kaldırılırken genel bir hata oluştu: {e}"
# ==============================================================================
### CIS 2.1.1: autofs Servisinin Kullanımda Olmadığından Emin Ol ###

def check_automount_block (username, parameters):
    """
    'autofs' paketinin sistemde kurulu olup olmadığını kontrol eder.
    Eğer paket kurulu ise, kaldırmak veya maskelemek için 'apply' fonksiyonunu çağırır.
    """
    package_name = "autofs"
    
    # dpkg -l komutu paketin durumunu kontrol eder.
    # Çıktıda 'ii  autofs' varsa, paket kurulu demektir.
    success, output = run_command(['dpkg', '-l', package_name])
    
    if f"ii  {package_name}" in output:
        # Paket kurulu ise, uyumsuz durumdadır ve düzeltilmesi gerekir.
        logger.info(f"'{package_name}' paketi kurulu, düzeltme uygulanıyor.")
        return apply_autofs_removal_or_masking()
    else:
        # Paket kurulu değilse, sistem zaten uyumludur.
        return True, f"'{package_name}' paketi sistemde kurulu değil."

def apply_autofs_removal_or_masking():
    """
    Önce 'autofs' paketini kaldırmayı (purge) dener.
    Eğer bu, bağımlılıklar nedeniyle başarısız olursa, servisi durdurup maskeler.
    """
    package_name = "autofs"
    service_name = "autofs.service"

    # --- BİRİNCİL ÇÖZÜM: Paketi tamamen kaldırmayı dene ---
    logger.info(f"Birincil çözüm deneniyor: '{package_name}' paketi kaldırılacak (purge)...")
    success, output = run_command(['sudo', 'apt-get', 'purge', '-y', package_name])
    
    if success:
        return True, f"'{package_name}' paketi ve yapılandırma dosyaları başarıyla kaldırıldı."

    # --- İKİNCİL ÇÖZÜM: Eğer purge başarısız olursa, servisi maskele ---
    logger.warning(f"'{package_name}' paketi kaldırılamadı (muhtemelen başka bir pakete bağımlı).")
    logger.info(f"İkincil çözüm deneniyor: '{service_name}' servisi durdurulup maskelenecek...")

    # Önce servisi durdur
    run_command(['sudo', 'systemctl', 'stop', service_name])
    
    # Sonra servisi maskele (tekrar başlamasını kalıcı olarak engeller)
    success, output = run_command(['sudo', 'systemctl', 'mask', service_name])
    
    if success:
        return True, f"'{service_name}' servisi başarıyla durduruldu ve maskelendi."
    else:
        return False, f"'{service_name}' servisi maskelenirken hata: {output}"