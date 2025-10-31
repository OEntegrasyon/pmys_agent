import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


def revert_apparmor_settings():
    """
    Sistem genelindeki AppArmor ayarlarını 'varsayılan' (default) duruma
    döndürür. 
    
    Bu betik, 'apply_enforce_all_profiles' (Politika 4) tarafından yapılan
    'enforce' (sıkı) mod değişikliğini geri alır.
    
    'apply' kodunun tersi olarak, tüm profilleri 'complain' (şikayet/loglama)
    moduna alır. Bu, sistem açılışı için güvenli bir varsayılan durumdur.
    
    NOT: Bu kod, GRUB veya paket kurulumu gibi tehlikeli ve geri
    alınmaması gereken (baseline) ayarları DEĞİŞTİRMEZ.
    """
    logger.info("[DEFAULT] AppArmor profilleri 'complain' (varsayılan) moda alınıyor...")

    # 'aa-enforce /etc/apparmor.d/*' komutunun tersi,
    # 'aa-complain /etc/apparmor.d/*' komutudur.
    complain_cmd = ['sudo', 'aa-complain', '/etc/apparmor.d/*']
    
    # Değişiklikleri etkinleştirmek için 'reload' komutunu da çalıştırmak
    reload_cmd = ['sudo', 'service', 'apparmor', 'reload']

    try:
        # 1. Tüm profilleri 'complain' moduna al
        success, output = run_command(complain_cmd)
        
        if not success:
            if "No such file" in output:
                 logger.warning("[DEFAULT] AppArmor yüklü görünmüyor ('aa-complain' bulunamadı). Revert atlanıyor.")
                 return True 
            else:
                logger.error(f"[DEFAULT] 'aa-complain' komutu çalıştırılırken hata: {output}")
                return False

        # 2. Servisi yeniden yükle
        success, output = run_command(reload_cmd)

        if not success:
             logger.error(f"[DEFAULT] AppArmor servisi 'reload' edilirken hata: {output}")
             return False

        logger.info("[DEFAULT] AppArmor profilleri başarıyla 'complain' moduna (varsayılan) alındı.")
        return True

    except Exception as e:
        logger.error(f"[DEFAULT] AppArmor profilleri geri alınırken genel hata: {e}")
        return False