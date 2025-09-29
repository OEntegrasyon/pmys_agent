import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


def revert_login_banners():
    """
    /etc/motd, /etc/issue ve /etc/issue.net dosyalarını silerek
    giriş başlıklarını varsayılan durumuna getirir.
    """
    banner_files = ["/etc/motd", "/etc/issue", "/etc/issue.net"]
    logger.info("[DEFAULT] Giriş başlıkları kontrol ediliyor...")

    for file_path in banner_files:
        # CIS politikası bu dosyayı oluşturmuş veya değiştirmiş mi diye kontrol et.
        if os.path.exists(file_path):
            try:
                # Pardus'un varsayılanında bu dosyalar genellikle boştur veya sadece
                # sistem bilgisi içerir. Güvenli varsayılan, bu dosyaları silmektir.
                logger.info(f"[DEFAULT] '{file_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', file_path])
                if not success:
                    logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {output}")
                    continue
                logger.info(f"[DEFAULT] '{file_path}' başarıyla varsayılana döndürüldü (kaldırıldı).")
            except Exception as e:
                logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {e}")
        else:
            logger.info(f"[DEFAULT] '{file_path}' zaten mevcut değil (varsayılan durum).")