import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;


def revert_apparmor_settings():
    """
    GRUB yapılandırmasına eklenen AppArmor parametrelerini kaldırır.
    """
    config_path = "/etc/default/grub"
    if not os.path.exists(config_path):
        return

    with open(config_path, "r") as f:
        content = f.read()

    # Eğer CIS politikası bir değişiklik yapmışsa (parametreler ekliyse)
    if "apparmor=1" in content or "security=apparmor" in content:
        logger.info("[DEFAULT] GRUB'dan AppArmor parametreleri kaldırılıyor...")
        # Parametreleri boşlukla değiştirerek temizle
        new_content = re.sub(r'\s*apparmor=1\s*', ' ', content)
        new_content = re.sub(r'\s*security=apparmor\s*', ' ', new_content)

        # GRUB_CMDLINE_LINUX satırındaki çift boşlukları tek boşluğa indir
        new_content = re.sub(r'GRUB_CMDLINE_LINUX="([^"]*)"', lambda m: f'GRUB_CMDLINE_LINUX="{" ".join(m.group(1).split())}"', new_content)

        temp_path = "/tmp/grub.revert"
        with open(temp_path, "w") as f:
            f.write(new_content)

        success , output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            logger.error(f"[DEFAULT] GRUB yapılandırması geri alınamadı: {output}")
            return

        success, output = run_command(['sudo', 'update-grub'])
        if not success:
            logger.error(f"[DEFAULT] GRUB güncellenirken hata: {output}")
            return
        logger.info("[DEFAULT] GRUB başarıyla varsayılana döndürüldü.")