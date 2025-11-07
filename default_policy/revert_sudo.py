import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

def revert_sudo_settings():
    """
    Sistem açılışında,  (CIS) politikası tarafından /etc/sudoers.d/ altına 
    eklenmiş olan SİSTEM GENELİ ('01-sudo-logging') ve KULLANICI BAZLI 
    ('{username}-restricted', vb.) yapılandırma dosyalarını kaldırır.
    """
    logger.info("[DEFAULT] Sudo ayarları (Sistem Geneli ve Kullanıcı Bazlı) geri alınıyor...")
    
    sudoers_dir = "/etc/sudoers.d/"
    
    # Korunması gereken, sistemin orijinalinde olan dosyalar.
    # '01-sudo-logging' bu listeden çıkarıldı çünkü o CIS tarafından eklendi.
    baseline_files_to_keep = {
        "README" 
    }


    policy_files_to_remove = {
        "01-sudo-logging"
        # Başka bir sistem geneli politika dosyası eklediyseniz buraya ekleyin
    }

    dynamic_suffixes_to_remove = (
        "-restricted",
        "-nopasswd",
        "-usermgmt"
    )

    if not os.path.isdir(sudoers_dir):
        logger.warning(f"[DEFAULT] Sudoers dizini '{sudoers_dir}' bulunamadı, işlem atlanıyor.")
        return

    try:
        for filename in os.listdir(sudoers_dir):
            file_path = os.path.join(sudoers_dir, filename)
            
            # 1. Korumamız gereken temel dosyalara dokunma
            if filename in baseline_files_to_keep:
                logger.info(f"[DEFAULT] Baseline kuralı '{filename}' korundu (silinmedi).")
                continue 

            # 2. Silinmesi gereken politika dosyalarını sil
            if filename in policy_files_to_remove:
                logger.info(f"[DEFAULT] SİSTEM GENELİ politika kuralı '{file_path}' kaldırılıyor...")
                _delete_sudoer_file(file_path)
                continue

            # 3. Dinamik (kullanıcı bazlı) politika dosyalarını sil
            if filename.endswith(dynamic_suffixes_to_remove):
                logger.info(f"[DEFAULT] KULLANICI kuralı '{file_path}' kaldırılıyor...")
                _delete_sudoer_file(file_path)
                continue
            
            # 4. Yukarıdaki kurallara uymayanları koru
            logger.info(f"[DEFAULT]   dosya '{filename}' atlandı (korundu).")

        logger.info("[DEFAULT] Sudo (Sistem Geneli ve Kullanıcı Bazlı) temizlik tamamlandı.")
        
    except Exception as e:
        logger.error(f"[DEFAULT] Sudo ayarları geri alınırken genel bir hata oluştu: {e}")

def _delete_sudoer_file(file_path):
    """Verilen sudoers dosyasını siler."""
    try:
        success, output = run_command(['sudo', 'rm', '-f', file_path])
        if not success:
            logger.error(f"[DEFAULT] '{file_path}' silinirken hata: {output}")
    except Exception as e:
        logger.error(f"[DEFAULT] '{file_path}' silinirken istisna: {e}")