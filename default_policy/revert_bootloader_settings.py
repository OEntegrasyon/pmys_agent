import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command

# __init__.py tarafından çağrılacak olan ana YÖNETİCİ fonksiyon
def revert_bootloader_settings():
    """Bootloader ile ilgili TÜM geri alma işlemlerini yönetir."""
    logger.info("[DEFAULT] Bootloader ayarları kontrol ediliyor...")
    _revert_bootloader_password()
    _revert_bootloader_permissions()

# Bu fonksiyonlar artık bu dosyanın "iç" fonksiyonlarıdır.
# Başına _ koyarak "private" (özel) olduğunu belirtebiliriz (isteğe bağlı).
def _revert_bootloader_password():
    """GRUB parola dosyasını kaldırır."""
    auth_file_path = "/etc/grub.d/01_security"
    if os.path.exists(auth_file_path):
        logger.info(f"[DEFAULT] GRUB parola dosyası '{auth_file_path}' kaldırılıyor...")
        run_command(['sudo', 'rm', '-f', auth_file_path])
        run_command(['sudo', 'update-grub'])

def _revert_bootloader_permissions():
    """grub.cfg dosyasının izinlerini varsayılan olan '644'e geri döndürür."""
    grub_cfg_path = _find_grub_cfg_path()
    if not grub_cfg_path:
        return

    current_perms_str = oct(stat.S_IMODE(os.stat(grub_cfg_path).st_mode))[-3:]
    if current_perms_str != '644':
        logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri '644' olarak düzeltiliyor...")
        run_command(['sudo', 'chmod', '644', grub_cfg_path])

def _find_grub_cfg_path():
    """grub.cfg dosyasının yaygın konumlarını arar."""
    for path in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
        if os.path.exists(path):
            return path
    return None