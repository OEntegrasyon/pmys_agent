import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

PACKAGES_TO_REINSTALL = [
    "telnet",
    "nis",
    "rsh-client",
    "talk"
]

def revert_package_removals():
    """
    CIS politikası tarafından kaldırılmış olabilecek güvensiz paketleri
    sisteme yeniden yükler.
    """
    logger.info("[DEFAULT] Kaldırılmış paketler kontrol ediliyor...")
    
    try:
        # Paket listesini güncellemek her zaman iyi bir pratiktir.
        logger.info("[DEFAULT] Paket listesi güncelleniyor (apt-get update)...")
        success, output = run_command(['sudo', 'apt-get', 'update'])
        if not success:
            logger.warning(f"[DEFAULT] apt-get update başarısız oldu: {output}. Yine de devam ediliyor.")
    except Exception as e:
        logger.warning(f"[DEFAULT] apt-get update başarısız oldu, yine de devam ediliyor: {e}")

    for package_name in PACKAGES_TO_REINSTALL:
        try:
            # Paketin kurulu olup olmadığını kontrol et
            success, output = run_command(['dpkg', '-l', package_name])
            if not success or f"ii  {package_name}" not in output:
                logger.info(f"[DEFAULT] '{package_name}' paketi kurulu değil, varsayılana döndürmek için YÜKLENİYOR...")
                
                # Paketi yeniden yükle
                success, output = run_command(
                    ['sudo', 'apt-get', 'install', '-y', package_name]
                )
                if not success:
                    logger.error(f"[DEFAULT] '{package_name}' paketi yüklenirken hata: {output}")
                    return
                logger.info(f"[DEFAULT] '{package_name}' paketi başarıyla yüklendi.")
            else:
                # Paket zaten kuruluysa, bir şey yapmaya gerek yok.
                logger.info(f"[DEFAULT] '{package_name}' paketi zaten kurulu (varsayılan durum).")
        except Exception as e:
            logger.error(f"[DEFAULT] '{package_name}' paketi işlenirken genel hata: {e}")