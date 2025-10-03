import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

def revert_sudo_settings():
    """
    Ajan tarafından /etc/sudoers.d/ altına eklenmiş olan tüm yapılandırma
    dosyalarını ('pmys-' ve '01-pmys-' önekli) kaldırır.
    """
    logger.info("[DEFAULT] Sudo ayarları kontrol ediliyor...")
    
    sudoers_dir = "/etc/sudoers.d/"
    # Ajanımızın oluşturduğu dosya önekleri
    prefixes_to_remove = ("pmys-", "01-pmys-")
    
    if not os.path.isdir(sudoers_dir):
        logger.warning(f"[DEFAULT] Sudoers dizini '{sudoers_dir}' bulunamadı, işlem atlanıyor.")
        return
        
    try:
        # Dizin içindeki tüm dosyaları tara
        for filename in os.listdir(sudoers_dir):
            # Eğer dosya adı bizim özel öneklerimizden biriyle başlıyorsa
            if filename.startswith(prefixes_to_remove):
                file_path = os.path.join(sudoers_dir, filename)
                try:
                    logger.info(f"[DEFAULT] Ajan tarafından oluşturulan sudo kuralı '{file_path}' kaldırılıyor...")
                    # Dosyayı sudo ile güvenli bir şekilde sil
                    success, output = run_command(['sudo', 'rm', '-f', file_path])
                    if not success:
                        logger.error(f"[DEFAULT] '{file_path}' silinirken hata: {output}")
                except Exception as e:
                    logger.error(f"[DEFAULT] '{file_path}' işlenirken hata: {e}")

        logger.info("[DEFAULT] Sudo ayarları için temizlik tamamlandı.")
        
    except Exception as e:
        logger.error(f"[DEFAULT] Sudo ayarları geri alınırken genel bir hata oluştu: {e}")
