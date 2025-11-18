import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


MODULES_TO_RE_ENABLE = [
    "dccp",
    "tipc",
    "rds",
    "sctp"
]

def revert_disabled_network_modules():
    """
    CIS 3.2.x politikaları tarafından /etc/modprobe.d/ içinde oluşturulmuş olan
    AĞ MODÜLÜ engelleme dosyalarını kaldırır.
    """
    logger.info("[DEFAULT] Devre dışı bırakılmış AĞ modülleri kontrol ediliyor...")
    
    reverted_count = 0
    
    for module_name in MODULES_TO_RE_ENABLE:
        rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
        
        try:
            if os.path.exists(rule_path):
                logger.info(f"[DEFAULT] '{module_name}' ağ modülü için engelleme kuralı kaldırılıyor...")
                
                success, output = run_command(['sudo', 'rm', '-f', rule_path])
                
                if not success:
                    logger.error(f"[DEFAULT] '{module_name}' modül kuralı kaldırılırken hata: {output}")
                    continue
                else:
                    logger.info(f"[DEFAULT] '{module_name}' modül kuralı başarıyla kaldırıldı.")
                    reverted_count += 1
            else:
                logger.info(f"[DEFAULT] '{module_name}' ağ modülü zaten etkin (varsayılan durum).")

        except Exception as e:
            logger.error(f"[DEFAULT] '{module_name}' ağ modülü geri alınırken hata: {e}")

    logger.info(f"[DEFAULT] Ağ modülleri revert işlemi tamamlandı. {reverted_count} kural kaldırıldı.")
    return True