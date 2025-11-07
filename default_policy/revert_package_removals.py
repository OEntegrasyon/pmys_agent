import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


def revert_services_settings():
    """Servislerle ilgili TÜM geri alma işlemlerini yönetir."""
    logger.info("[DEFAULT] Servis ayarları kontrol ediliyor...")
    _revert_autofs_service()
    _revert_package_removals()

PACKAGES_TO_REINSTALL = [
    "inetutils-telnetd"
]

def _revert_package_removals():
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



def _revert_autofs_service():
    """
    'autofs' servisi için yapılan değişiklikleri geri alır.
    Servis maskelenmişse maskeyi kaldırır, paket kaldırılmışsa paketi yeniden kurar.
    """
    package_name = "autofs"
    service_name = "autofs.service"

    try:
        # CIS politikasının ikincil çözümünü (maskeleme) geri al.
        success, output = run_command(['systemctl', 'is-enabled', service_name])
        if success and "masked" in output:
            logger.info(f"[DEFAULT] '{service_name}' maskelenmiş, maske kaldırılıyor...")
            run_command(['sudo', 'systemctl', 'unmask', service_name])
            logger.info(f"[DEFAULT] '{service_name}' servisi başarıyla yeniden etkinleştirildi.")
            return

        # CIS politikasının birincil çözümünü (purge) geri al.
        success, output = run_command(['dpkg', '-l', package_name])
        if f"ii  {package_name}" not in output:
            logger.info(f"[DEFAULT] '{package_name}' paketi kurulu değil, yeniden kuruluyor...")
            # Paketi yeniden kur
            update_success, _ = run_command(['sudo', 'apt-get', 'update'], timeout=120)
            if not update_success:
                 logger.warning("[DEFAULT] apt-get update başarısız oldu, yine de kuruluma devam ediliyor.")

            install_success, install_output = run_command(['sudo', 'apt-get', 'install', '-y', package_name])
            if install_success:
                logger.info(f"[DEFAULT] '{package_name}' paketi başarıyla kuruldu.")
            else:
                logger.error(f"[DEFAULT] '{package_name}' paketi kurulurken hata: {install_output}")
        else:
            logger.info(f"[DEFAULT] '{package_name}' paketi zaten kurulu (varsayılan durum).")

    except Exception as e:
        logger.error(f"[DEFAULT] autofs geri alınırken genel bir hata oluştu: {e}")


