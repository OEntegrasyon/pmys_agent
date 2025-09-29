import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def revert_interface_protocols():
    """
    Kablosuz ve Bluetooth için yapılan değişiklikleri geri alır.
    """
    logger.info("[DEFAULT] Arayüz ve protokol ayarları kontrol ediliyor...")
    
    # Kablosuz için oluşturulan blacklist dosyasını sil
    wifi_blacklist_file = "/etc/modprobe.d/pmys-wifi-blacklist.conf"
    if os.path.exists(wifi_blacklist_file):
        try:
            logger.info(f"[DEFAULT] Kablosuz arayüz engelleme kuralı '{wifi_blacklist_file}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', wifi_blacklist_file])
            if not success:
                logger.error(f"[DEFAULT] Kablosuz arayüz engelleme kuralı kaldırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Kablosuz arayüz engelleme kuralı başarıyla kaldırıldı.")
        except Exception as e:
            logger.error(f"[DEFAULT] Kablosuz arayüz kuralı geri alınırken hata: {e}")

    # Bluetooth servisini 'unmask' etmeyi dene
    # CIS politikası paketi kaldırmış veya servisi maskelemiş olabilir.
    # Geri alma işlemi servisi sadece 'unmask' eder, paketi yeniden kurmaz.
    try:
        success, output = run_command(['systemctl', 'is-enabled', 'bluetooth.service'])
        if "masked" in output:
            logger.info("[DEFAULT] Bluetooth servisi 'unmask' ediliyor...")
            success, output = run_command(['sudo', 'systemctl', 'unmask', 'bluetooth.service'])
            if not success:
                logger.error(f"[DEFAULT] Bluetooth servisi 'unmask' edilirken hata: {output}")
            else:
                logger.info("[DEFAULT] Bluetooth servisi başarıyla 'unmask' edildi.")
    except Exception as e:
         logger.error(f"[DEFAULT] Bluetooth servisi geri alınırken hata: {e}")
