import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


MODULES_TO_RE_ENABLE = [
    "cramfs",
    "freevxfs",
    "hfs",
    "hfsplus",
    "jffs2",
    "squashfs",
    "udf",
    "usb_storage"
]

def revert_disabled_modules():
    """
    CIS politikası tarafından /etc/modprobe.d/ içinde oluşturulmuş olan
    modül engelleme dosyalarını kaldırır.
    """
    logger.info("[DEFAULT] Devre dışı bırakılmış çekirdek modülleri kontrol ediliyor...")
    
    for module_name in MODULES_TO_RE_ENABLE:
        # CIS politikasının oluşturduğu dosyanın tam yolu
        rule_path = f"/etc/modprobe.d/{module_name}-cis-blacklist.conf"
        
        try:
            # Eğer bu dosya varsa, CIS politikası uygulanmış demektir.
            if os.path.exists(rule_path):
                logger.info(f"[DEFAULT] '{module_name}' modülü için engelleme kuralı kaldırılıyor...")
                
                # Dosyayı silerek modülün tekrar yüklenebilmesini sağla
                success, output = run_command(['sudo', 'rm', '-f', rule_path])
                if not success:
                    logger.error(f"[DEFAULT] '{module_name}' modül kuralı kaldırılırken hata: {output}")
                    continue
            else:
                # Dosya yoksa, sistem zaten varsayılan durumdadır.
                logger.info(f"[DEFAULT] '{module_name}' modülü zaten etkin (varsayılan durum).")

        except Exception as e:
            logger.error(f"[DEFAULT] '{module_name}' modülü geri alınırken hata: {e}")