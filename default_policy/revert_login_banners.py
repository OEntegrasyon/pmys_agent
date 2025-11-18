import os
import re
import stat
import subprocess
import tempfile
from logger import logger
from utils import run_command;

DEFAULT_MOTD_CONTENT = """
The programs included with the Pardus GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Pardus GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
"""

DEFAULT_ISSUE_CONTENT = "Pardus GNU/Linux 23 \\n \\l\n"
DEFAULT_ISSUE_NET_CONTENT = "Pardus GNU/Linux 23\n"

def revert_login_banners():
    """
    /etc/motd, /etc/issue ve /etc/issue.net dosyalarını Pardus'un
    varsayılan (default) içeriğine döndürür ve SSH banner ayarını kaldırır.
    """
    logger.info("[DEFAULT] Giriş başlıkları (banners) varsayılana döndürülüyor...")

    # 1. /etc/motd dosyasını varsayılana döndür
    _write_default_content("/etc/motd", DEFAULT_MOTD_CONTENT.strip())

    # 2. /etc/issue dosyasını varsayılana döndür
    _write_default_content("/etc/issue", DEFAULT_ISSUE_CONTENT)

    # 3. /etc/issue.net dosyasını varsayılana döndür
    _write_default_content("/etc/issue.net", DEFAULT_ISSUE_NET_CONTENT)

    # 4. SSHD yapılandırmasından Banner satırını kaldır
    _revert_ssh_banner()
    
    logger.info("[DEFAULT] Giriş başlıklarını (banners) geri alma işlemi tamamlandı.")

def _write_default_content(file_path, content):
    """
    Verilen içeriği geçici bir dosyaya yazar ve sudo ile hedefe taşır.
    Bu, 'echo' komutlarındaki 'permission denied' sorunlarını aşar.
    """
    try:
        # Geçici bir dosya oluştur
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        logger.info(f"[DEFAULT] '{file_path}' dosyası varsayılan içerikle güncelleniyor...")
        
        # Geçici dosyayı sudo ile asıl yerine taşı
        success, output = run_command(['sudo', 'mv', temp_file_path, file_path])
        if not success:
            logger.error(f"[DEFAULT] '{file_path}' güncellenirken (mv) hata: {output}")
            return

        # İzinleri ve sahipliği düzelt
        run_command(['sudo', 'chown', 'root:root', file_path])
        run_command(['sudo', 'chmod', '644', file_path])

    except Exception as e:
        logger.error(f"[DEFAULT] '{file_path}' içeriği geri alınırken istisna: {e}")
    finally:
        # Geçici dosya kalırsa temizle
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def _revert_ssh_banner():
    """
    /etc/ssh/sshd_config dosyasından 'Banner' satırını kaldırır.
    """
    sshd_config_path = "/etc/ssh/sshd_config"
    logger.info(f"[DEFAULT] '{sshd_config_path}' dosyasından 'Banner' ayarı kaldırılıyor...")

    try:
        # sed komutu ile 'Banner' ile başlayan satırı (yorum değilse) sil
        # Not: Bu, 'Banner /etc/issue.net' satırını kaldırır.
        sed_cmd = [
            'sudo', 'sed', '-i',
            r'/^Banner\s/d',
            sshd_config_path
        ]
        
        success, output = run_command(sed_cmd)
        if not success:
            logger.error(f"[DEFAULT] '{sshd_config_path}' düzenlenirken hata: {output}")
            return
            
        logger.info(f"[DEFAULT] '{sshd_config_path}' başarıyla varsayılana döndürüldü.")

        # SSH servisini yeniden yükle
        logger.info("[DEFAULT] SSH servisi yeniden yükleniyor (reload)...")
        success, output = run_command(['sudo', 'systemctl', 'reload', 'ssh'])
        if not success:
             logger.warning(f"[DEFAULT] SSH servisi yeniden yüklenemedi: {output}")

    except Exception as e:
        logger.error(f"[DEFAULT] '{sshd_config_path}' geri alınırken istisna: {e}")