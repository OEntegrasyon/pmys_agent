import os
import re
import stat
import subprocess
from logger import logger      
from utils import run_command  

SYSCTL_KEYS_TO_REVERT = [
    # 3.3.1
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    # 3.3.2
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    # 3.3.3
    "net.ipv4.icmp_ignore_bogus_error_responses",
    # 3.3.4
    "net.ipv4.icmp_echo_ignore_broadcasts",
    # 3.3.5
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    # 3.3.6
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.default.secure_redirects",
    # 3.3.7
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    # 3.3.8
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
    # 3.3.9
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.log_martians",
    # 3.3.10
    "net.ipv4.tcp_syncookies",
    # 3.3.11
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra"
]

def revert_sysctl_parameters():
    """
    CIS politikası tarafından /etc/sysctl.d/ altında oluşturulmuş olan
    (60-*.conf) yapılandırma dosyalarını kaldırır ve sysctl 
    ayarlarını yeniden yükleyerek varsayılanlara döndürür.
    """
    logger.info("[DEFAULT] Ağ (Sysctl) parametreleri geri alınıyor...")
    
    config_dir = "/etc/sysctl.d/"
    changes_made = False
    
    for key in SYSCTL_KEYS_TO_REVERT:
        # 'apply_sysctl_parameter' fonksiyonunda kullanılan
        # dosya adlandırma mantığı ile eşleşmelidir.
        config_filename = key.replace('.', '_').replace('/', '_')

        config_path = f"{config_dir}60-{config_filename}.conf"
        
        try:
            if os.path.exists(config_path):
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{config_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', config_path])
                
                if not success:
                    logger.error(f"[DEFAULT] '{config_path}' kaldırılırken hata: {output}")
                else:
                    changes_made = True
            else:
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{config_path}' zaten yok (varsayılan).")
        
        except Exception as e:
            logger.error(f"[DEFAULT] '{config_path}' kaldırılırken beklenmedik hata: {e}")

    # Eğer en az bir dosya silindiyse, çalışan sysctl ayarlarını yeniden yükle
    if changes_made:
        try:
            logger.info("[DEFAULT] Sysctl ayarları (çalışan sistem) varsayılanlara döndürülüyor...")
            
            # 'sysctl --system' komutu, /etc/sysctl.d/ içindeki *kalan*
            # tüm .conf dosyalarını okur ve uygular.
            success, output = run_command(['sudo', 'sysctl', '--system'])
            
            if not success:
                logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
        
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken istisna: {e}")
    else:
        logger.info("[DEFAULT] Ağ ayarları için eklenmiş  sysctl kuralı bulunamadı.")

    logger.info("[DEFAULT] Ağ (Sysctl) parametrelerini geri alma işlemi tamamlandı.")
    return True