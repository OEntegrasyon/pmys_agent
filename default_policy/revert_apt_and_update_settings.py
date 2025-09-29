import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def revert_apt_and_update_settings():
    """
    APT depo listesi ve otomatik güncelleme betiği değişikliklerini geri alır.
    """
    logger.info("[DEFAULT] APT ve güncelleme ayarları kontrol ediliyor...")
    
    # 1. Otomatik güncelleme için oluşturulan cron betiğini sil
    cron_script_path = "/etc/cron.daily/pmys-automatic-updates"
    if os.path.exists(cron_script_path):
        try:
            logger.info(f"[DEFAULT] Otomatik güncelleme betiği '{cron_script_path}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', cron_script_path])
            if not success:
                logger.error(f"[DEFAULT] Otomatik güncelleme betiği kaldırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Otomatik güncelleme betiği başarıyla kaldırıldı.")
        except Exception as e:
            logger.error(f"[DEFAULT] Otomatik güncelleme betiği kaldırılırken hata: {e}")
    else:
        logger.info("[DEFAULT] Otomatik güncelleme betiği zaten mevcut değil (varsayılan durum).")

    # 2. Değiştirilen sources.list dosyasını, oluşturulan yedekten geri yükle
    sources_path = "/etc/apt/sources.list"
    # Yedek dosyalarını bulmak için /etc/apt dizinini tara
    backup_dir = "/etc/apt/"
    backup_files = [f for f in os.listdir(backup_dir) if f.startswith("sources.list.bak_")]
    
    if backup_files:
        # En son oluşturulan yedeği bul
        latest_backup = max(backup_files, key=lambda f: os.path.getmtime(os.path.join(backup_dir, f)))
        latest_backup_path = os.path.join(backup_dir, latest_backup)
        
        try:
            logger.info(f"[DEFAULT] '{sources_path}' en son yedekten ('{latest_backup}') geri yükleniyor...")
            success, output = run_command(['sudo', 'mv', latest_backup_path, sources_path])
            if not success:
                logger.error(f"[DEFAULT] '{sources_path}' geri yüklenirken hata: {output}")
            else:
                logger.info(f"[DEFAULT] '{sources_path}' başarıyla yedeğinden geri yüklendi. Paket listesi güncelleniyor...")
                run_command(['sudo', 'apt-get', 'update'])
                logger.info("[DEFAULT] Paket listesi başarıyla güncellendi.")
        except Exception as e:
            logger.error(f"[DEFAULT] '{sources_path}' geri yüklenirken hata: {e}")
    else:
        logger.info(f"[DEFAULT] '{sources_path}' için bir yedek dosyası bulunamadı, geri alma işlemi atlanıyor.")
