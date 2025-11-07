import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def revert_process_hardening():
    """
    ASLR, ptrace ve core dump için server tarafından oluşturulmuş 
    sysctl.d ve limits.d yapılandırma dosyalarını kaldırarak ayarları
    varsayılan (default) durumuna geri döndürür.
    """
    logger.info("[DEFAULT] Çekirdek güvenliği (Process Hardening) ayarları geri alınıyor...")

    # ==========================================================================
    # 1. Sysctl (.conf) dosyalarını kaldır
    # ==========================================================================
    sysctl_files_to_remove = [
        "/etc/sysctl.d/99-aslr-hardening.conf",
        "/etc/sysctl.d/99-ptrace-hardening.conf",
        "/etc/sysctl.d/99-coredump-hardening.conf"
    ]
    
    changes_made = False
    
    for file_path in sysctl_files_to_remove:
        try:
            if os.path.exists(file_path):
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{file_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', file_path])
                
                if not success:
                    logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {output}")
                else:
                    changes_made = True
            else:
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{file_path}' zaten yok (varsayılan).")
        
        except Exception as e:
            logger.error(f"[DEFAULT] '{file_path}' kaldırılırken beklenmedik hata: {e}")
    
    # Eğer en az bir sysctl dosyası silindiyse, çalışan ayarları yeniden yükle
    if changes_made:
        try:
            logger.info("[DEFAULT] Sysctl ayarları (çalışan sistem) varsayılanlara döndürülüyor...")
            # '--system', kaldırılan dosyaları hesaba katmayacak ve 
            # kalan .conf dosyalarına göre sistemi yeniden yükleyecektir.
            success, output = run_command(['sudo', 'sysctl', '--system'])
            
            if success:
                logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
            else:
                logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {output}")
        
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken istisna: {e}")
    else:
        logger.info("[DEFAULT] Process hardening için eklenmiş sysctl kuralı bulunamadı.")


    # ==========================================================================
    # 2. limits.d (.conf) dosyasını kaldır 
    # ==========================================================================
    
    limits_path_to_remove = "/etc/security/limits.d/99-coredump-hardening.conf"
    
    try:
        if os.path.exists(limits_path_to_remove):
            logger.info(f"[DEFAULT] 'limits.d' kural dosyası '{limits_path_to_remove}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', limits_path_to_remove])
            
            if not success:
                logger.error(f"[DEFAULT] '{limits_path_to_remove}' kaldırılırken hata: {output}")
            else:
                # 'limits.d' ayarlarının anlık bir 'yeniden yükle' komutu yoktur.
                # Değişiklik, bir sonraki 'login' (oturum açma) işleminde geçerli olacaktır.
                logger.info(f"[DEFAULT] '{limits_path_to_remove}' başarıyla kaldırıldı. (Varsayılan limitler bir sonraki oturumda geçerli olacak)")
        else:
            logger.info(f"[DEFAULT] Core dump için eklenmiş 'limits.d' kuralı bulunamadı.")
            
    except Exception as e:
        logger.error(f"[DEFAULT] '{limits_path_to_remove}' kaldırılırken beklenmedik hata: {e}")

    logger.info("[DEFAULT] Process Hardening revert işlemi tamamlandı.")
    return True