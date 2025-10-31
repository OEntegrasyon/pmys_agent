import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

def revert_sudo_settings():
    """
    Sistem açılışında, ajan tarafından /etc/sudoers.d/ altına eklenmiş olan
    KULLANICI BAZLI ('{username}-restricted', '{username}-nopasswd', vb.)
    yapılandırma dosyalarını kaldırır.
    
    SİSTEM GENELİ ('01-sudo-logging') kurallara dokunmaz.
    """
    logger.info("[DEFAULT] Sudo ayarları (kullanıcı bazlı) geri alınıyor...")
    
    sudoers_dir = "/etc/sudoers.d/"
    

    baseline_files_to_keep = {
        "01-sudo-logging", 
        "README"           
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
            
            if filename in baseline_files_to_keep:
                logger.info(f"[DEFAULT] Baseline (Sistem Geneli) kuralı '{filename}' korundu (silinmedi).")
                continue 

            if filename.endswith(dynamic_suffixes_to_remove):
                file_path = os.path.join(sudoers_dir, filename)
                try:
                    logger.info(f"[DEFAULT] Ajan tarafından oluşturulan KULLANICI kuralı '{file_path}' kaldırılıyor...")
                    success, output = run_command(['sudo', 'rm', '-f', file_path])
                    if not success:
                        logger.error(f"[DEFAULT] '{file_path}' silinirken hata: {output}")
                except Exception as e:
                    logger.error(f"[DEFAULT] '{file_path}' işlenirken hata: {e}")
            else:
                logger.info(f"[DEFAULT] GPOS tarafından yönetilmeyen dosya '{filename}' atlandı (korundu).")

        logger.info("[DEFAULT] Sudo (kullanıcı bazlı) ayarlar için temizlik tamamlandı.")
        
    except Exception as e:
        logger.error(f"[DEFAULT] Sudo ayarları geri alınırken genel bir hata oluştu: {e}")