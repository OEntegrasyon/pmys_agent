import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

SYSCTL_KEYS_TO_REVERT = [
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.tcp_syncookies",
    "net.ipv6.conf.all.accept_ra"
]

def revert_sysctl_parameters():
    """
    CIS politikası tarafından /etc/sysctl.d/ altında oluşturulmuş olan
    yapılandırma dosyalarını kaldırır ve sysctl ayarlarını yeniden yükler.
    """
    logger.info("[DEFAULT] Sysctl parametreleri kontrol ediliyor...")
    
    config_dir = "/etc/sysctl.d/"
    changes_made = False
    
    for key in SYSCTL_KEYS_TO_REVERT:
        # Politikanın oluşturduğu dosya adını bul
        config_filename = key.replace('.', '_').replace('/', '_')
        config_path = f"{config_dir}99-pmys-{config_filename}.conf"
        
        if os.path.exists(config_path):
            try:
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{config_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', config_path])
                if not success:
                    logger.error(f"[DEFAULT] '{config_path}' kaldırılırken hata: {output}")
                changes_made = True
            except Exception as e:
                logger.error(f"[DEFAULT] '{config_path}' kaldırılırken hata: {e}")

    # Eğer en az bir dosya silindiyse, sysctl ayarlarını yeniden yükle
    if changes_made:
        try:
            logger.info("[DEFAULT] Sysctl ayarları yeniden yükleniyor...")
            # '-p' parametresi olmadan çalıştırmak, varsayılan dosyalardan ayarları yeniden okur.
            success, output = run_command(['sudo', 'sysctl', '--system'])
            if not success:
                logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {e}")