import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


# 'enforce_file_permissions' politikasının hedeflediği dosyaların
# varsayılan (genellikle daha az kısıtlayıcı) izinlerini burada tanımlayabiliriz.
DEFAULT_FILE_PERMISSIONS = {
    "/etc/passwd": "644",
    "/etc/shadow": "640", # Bu zaten varsayılan ve güvenli, yine de kontrol listesinde
    "/etc/group": "644",
    "/etc/gshadow": "640" # Bu da varsayılan ve güvenli
}

def revert_file_permissions_and_ownership():
    """
    Dosya izinleri ve sahipliği ile ilgili yapılan değişiklikleri geri alır.
    'audit_and_fix_unowned_files' gibi politikaların geri alınması genellikle istenmez,
    çünkü sahipsiz bir dosya her zaman bir güvenlik açığıdır. Bu yüzden o atlanmıştır.
    """
    logger.info("[DEFAULT] Dosya izin ve sahiplik ayarları kontrol ediliyor...")

    # 1. 'enforce_file_permissions' politikasının değiştirdiği izinleri geri al
    for file_path, default_perm in DEFAULT_FILE_PERMISSIONS.items():
        if os.path.exists(file_path):
            try:
                current_perms = oct(stat.S_IMODE(os.stat(file_path).st_mode))[-3:]
                if current_perms != default_perm:
                    logger.info(f"[DEFAULT] '{file_path}' izinleri varsayılana ({default_perm}) döndürülüyor...")
                    success, output = run_command(['sudo', 'chmod', default_perm, file_path])
                    if not success:
                        logger.error(f"[DEFAULT] '{file_path}' izinleri güncellenirken hata: {output}")
                        return
                    logger.info(f"[DEFAULT] '{file_path}' izinleri başarıyla varsayılana döndürüldü.")
                else:
                    logger.info(f"[DEFAULT] '{file_path}' izinleri zaten varsayılan durumda ({current_perms}).")
            except Exception as e:
                logger.error(f"[DEFAULT] '{file_path}' izinleri geri alınırken hata: {e}")


    logger.info("[DEFAULT] 'World-writable' dosyalar için geri alma işlemi atlanıyor (güvenlik nedeniyle).")

    logger.info("[DEFAULT] 'Unowned files' için geri alma işlemi atlanıyor (güvenlik nedeniyle).")