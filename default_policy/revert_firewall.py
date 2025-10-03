import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

def revert_firewall_settings():
    """
    UFW (Uncomplicated Firewall) tarafından yapılan tüm değişiklikleri geri alır.
    Tüm kuralları siler ve servisi devre dışı bırakır.
    """
    logger.info("[DEFAULT] Güvenlik duvarı (UFW) durumu kontrol ediliyor...")
    try:
        # Önce UFW'nin durumunu kontrol et
        success, status_output = run_command(['sudo', 'ufw', 'status'])

        # Eğer 'ufw' komutu başarısız olursa (örn: kurulu değilse), geri alınacak bir şey yoktur.
        if not success:
            logger.info("[DEFAULT] UFW kurulu değil veya durumu alınamıyor (varsayılan durum).")
            return

        # Eğer UFW aktif ise ('Status: active' içeriyorsa)
        if "Status: active" in status_output:
            logger.info("[DEFAULT] UFW aktif, varsayılan duruma sıfırlanıyor...")

            # 'ufw reset' komutu, tüm kuralları siler, varsayılanları 'allow' yapar ve UFW'yi devre dışı bırakır.
            reset_success, reset_output = run_command(['sudo', 'ufw', '--force', 'reset'])

            if reset_success:
                logger.info("[DEFAULT] UFW başarıyla sıfırlandı ve devre dışı bırakıldı.")
            else:
                logger.error(f"[DEFAULT] UFW sıfırlanırken hata: {reset_output}")
        else:
            logger.info("[DEFAULT] UFW zaten aktif değil (varsayılan durum).")

    except Exception as e:
        logger.error(f"[DEFAULT] UFW geri alınırken genel bir hata oluştu: {e}")