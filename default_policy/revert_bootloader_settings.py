import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

def revert_bootloader_settings():
    """
    Bootloader ile ilgili TÜM yapılandırmalarını geri alır.
    (Parola dosyası, 10_linux değişikliği ve grub.cfg izinleri)
    """
    logger.info("[DEFAULT] Bootloader ayarları varsayılana döndürülüyor...")
    
    _revert_bootloader_password()
    
    _revert_bootloader_permissions()
    
    logger.info("[DEFAULT] Bootloader revert işlemi tamamlandı.")

def _revert_bootloader_password():
    """
    GRUB parola dosyasını (/etc/grub.d/01_security) kaldırır,
    10_linux dosyasındaki '--unrestricted' bayrağını temizler
    ve 'update-grub' komutunu çalıştırır.
    """
    auth_file_path = "/etc/grub.d/01_security"
    linux_config_path = "/etc/grub.d/10_linux"
    
    changes_made = False

    # 1. 'apply' tarafından oluşturulan parola dosyasını sil
    try:
        if os.path.exists(auth_file_path):
            logger.info(f"[DEFAULT] GRUB parola dosyası '{auth_file_path}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', auth_file_path])
            if success:
                changes_made = True
            else:
                logger.error(f"[DEFAULT] '{auth_file_path}' silinirken hata: {output}")
        else:
             logger.info(f"[DEFAULT] GRUB parola dosyası '{auth_file_path}' zaten yok.")
    except Exception as e:
        logger.error(f"[DEFAULT] '{auth_file_path}' silinirken istisna: {e}")

    # 2. 'apply' tarafından 10_linux'e eklenen '--unrestricted' bayrağını kaldır
    try:
        if os.path.exists(linux_config_path):

            logger.info(f"[DEFAULT] '{linux_config_path}' dosyasından '--unrestricted' bayrağı temizleniyor...")
   
            sed_revert_cmd = [
                'sudo', 'sed', '-i',
                's/ --unrestricted//g',
                linux_config_path
            ]
            
            success, output = run_command(sed_revert_cmd)
            if success:
                changes_made = True 
            else:
                 logger.error(f"[DEFAULT] '{linux_config_path}' temizlenirken hata: {output}")
        
        else:
            logger.warning(f"[DEFAULT] '{linux_config_path}' bulunamadı, --unrestricted temizlenemedi.")

    except Exception as e:
        logger.error(f"[DEFAULT] '{linux_config_path}' revert edilirken istisna: {e}")


    # 3. Eğer 1. veya 2. adımda bir değişiklik yapıldıysa 'update-grub' çalıştır
    if changes_made:
        try:
            logger.info("[DEFAULT] GRUB yapılandırması yeniden oluşturuluyor (update-grub)...")
            success, output = run_command(['sudo', 'update-grub'])
            if not success:
                logger.error(f"[DEFAULT] 'update-grub' çalıştırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] 'update-grub' başarıyla tamamlandı.")
        except Exception as e:
            logger.error(f"[DEFAULT] 'update-grub' çalıştırılırken istisna: {e}")
            

def _revert_bootloader_permissions():
    """grub.cfg dosyasının izinlerini varsayılan olan '644'e geri döndürür."""
    grub_cfg_path = _find_grub_cfg_path()
    if not grub_cfg_path:
        logger.warning("[DEFAULT] 'grub.cfg' dosyası bulunamadı, izinler geri alınamıyor.")
        return

    try:
        current_perms_str = oct(stat.S_IMODE(os.stat(grub_cfg_path).st_mode))[-3:]
        
        # Eğer '600' (CIS) ise '644' (varsayılan) yap.
        if current_perms_str == '600':
            logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri '644' (varsayılan) olarak düzeltiliyor...")
            success, output = run_command(['sudo', 'chmod', '644', grub_cfg_path])
            if not success:
                 logger.error(f"[DEFAULT] '{grub_cfg_path}' izinleri değiştirilirken hata: {output}")
        else:
            logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri zaten {current_perms_str} (600 değil).")
            
    except Exception as e:
        logger.error(f"[DEFAULT] '{grub_cfg_path}' izinleri geri alınırken istisna: {e}")


def _find_grub_cfg_path():
    """grub.cfg dosyasının yaygın konumlarını arar."""
    for path in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
        if os.path.exists(path):
            return path
    return None