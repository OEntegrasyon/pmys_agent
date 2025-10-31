import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def revert_interface_protocols():
    """
    Kablosuz (Wi-Fi), Bluetooth ve IPv6 için yapılan  politika
    değişikliklerini geri alır.
    
    Bu fonksiyonun sistem açılışında çalışarak sistemi varsayılan (default)
    ağ yapılandırmasına döndürmesi amaçlanmıştır.
    """
    logger.info("[DEFAULT] Arayüz, protokol ve IPv6 ayarları geri alınıyor...")
    
    # sysctl'de bir değişiklik yaparsak 'True' olacak
    sysctl_changes_made = False

    # ==========================================================================
    # 1. Kablosuz (Wi-Fi) kural dosyasını kaldır
    # ==========================================================================
    
    wifi_blacklist_file = "/etc/modprobe.d/wifi-blacklist.conf"

    try:
        if os.path.exists(wifi_blacklist_file):
            logger.info(f"[DEFAULT] Kablosuz arayüz engelleme kuralı '{wifi_blacklist_file}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', wifi_blacklist_file])
            
            if not success:
                logger.error(f"[DEFAULT] Kablosuz arayüz engelleme kuralı kaldırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Kablosuz arayüz engelleme kuralı başarıyla kaldırıldı.")
        else:
            logger.info(f"[DEFAULT] Kablosuz arayüz kuralı '{wifi_blacklist_file}' zaten yok (varsayılan).")
            
    except Exception as e:
        logger.error(f"[DEFAULT] Kablosuz arayüz kuralı geri alınırken beklenmedik hata: {e}")

    # ==========================================================================
    # 2. Bluetooth servisini 'unmask' et
    # ==========================================================================
    
    bluetooth_service = "bluetooth.service"
    
    try:
        # 'is-enabled' komutu, 'masked' durumunu da raporlar.
        success, output = run_command(['systemctl', 'is-enabled', bluetooth_service])
        
        if "masked" in output:
            logger.info("[DEFAULT] Bluetooth servisi 'unmask' ediliyor...")
            unmask_success, unmask_output = run_command(['sudo', 'systemctl', 'unmask', bluetooth_service])
            
            if not unmask_success:
                logger.error(f"[DEFAULT] Bluetooth servisi 'unmask' edilirken hata: {unmask_output}")
            else:
                logger.info("[DEFAULT] Bluetooth servisi başarıyla 'unmask' edildi.")
        else:
             logger.info(f"[DEFAULT] Bluetooth servisi zaten 'masked' değil (varsayılan).")

    except Exception as e:
           logger.error(f"[DEFAULT] Bluetooth servisi geri alınırken beklenmedik hata: {e}")

    # ==========================================================================
    # 3. IPv6 politika dosyasını kaldır 
    # ==========================================================================
    
    # 'apply_ipv6_enable' veya 'apply_ipv6_disable' tarafından oluşturulan dosya
    ipv6_config_file = "/etc/sysctl.d/99-ipv6-policy.conf"
    
    try:
        if os.path.exists(ipv6_config_file):
            logger.info(f"[DEFAULT] IPv6 politika dosyası '{ipv6_config_file}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', ipv6_config_file])
            
            if not success:
                logger.error(f"[DEFAULT] '{ipv6_config_file}' kaldırılırken hata: {output}")
            else:
                # Dosya silindiği için sysctl'i yeniden yüklememiz gerekecek
                sysctl_changes_made = True
                logger.info(f"[DEFAULT] IPv6 politika dosyası '{ipv6_config_file}' başarıyla kaldırıldı.")
        else:
            logger.info(f"[DEFAULT] IPv6 politika dosyası '{ipv6_config_file}' zaten yok (varsayılan).")

    except Exception as e:
        logger.error(f"[DEFAULT] '{ipv6_config_file}' kaldırılırken beklenmedik hata: {e}")

    # ==========================================================================
    # 4. Sysctl ayarlarını yeniden yükle 
    # ==========================================================================
    
    if sysctl_changes_made:
        try:
            logger.info("[DEFAULT] IPv6 değişikliği nedeniyle sysctl ayarları yeniden yükleniyor...")
            
            success, output = run_command(['sudo', 'sysctl', '--system'])
            
            if not success:
                logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
        
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken istisna: {e}")

    logger.info("[DEFAULT] Arayüz/Protokol/IPv6 revert işlemi tamamlandı.")
    return True