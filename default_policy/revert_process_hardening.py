import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def revert_process_hardening():
    """
    ASLR, ptrace ve core dump için yapılan sysctl ve limits.conf
    değişikliklerini geri alır.
    """
    logger.info("[DEFAULT] Çekirdek güvenliği (Process Hardening) ayarları kontrol ediliyor...")

    # 1. Sysctl dosyalarını kaldır
    sysctl_files_to_remove = [
        "/etc/sysctl.d/99-aslr-hardening.conf",
        "/etc/sysctl.d/99-ptrace-hardening.conf",
        "/etc/sysctl.d/99-coredump-hardening.conf"
    ]
    changes_made = False
    for file_path in sysctl_files_to_remove:
        if os.path.exists(file_path):
            try:
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{file_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', file_path])
                if not success:
                    logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {output}")
                changes_made = True
            except Exception as e:
                logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {e}")
    
    # Eğer en az bir sysctl dosyası silindiyse, ayarları yeniden yükle
    if changes_made:
        try:
            logger.info("[DEFAULT] Sysctl ayarları yeniden yükleniyor...")
            subprocess.run(['sudo', 'sysctl', '--system'], check=True)
            logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {e}")
    else:
        logger.info("[DEFAULT] Process hardening için eklenmiş sysctl kuralı bulunamadı.")


    # 2. limits.conf dosyasından core dump satırını kaldır
    limits_path = "/etc/security/limits.conf"
    if os.path.exists(limits_path):
        try:
            with open(limits_path, "r") as f:
                lines = f.readlines()

            # CIS politikası tarafından eklenen satırları ve yorumları içeren yeni bir liste oluştur
            new_lines = []
            skip_next = False
            modified = False
            for line in lines:
                if skip_next:
                    skip_next = False
                    continue
                if line.strip() == "# CIS: Core dumps disabled for security":
                    skip_next = True # Bir sonraki satırı da atla
                    modified = True
                    continue
                
                # Alternatif olarak, sadece kuralın kendisini de silebiliriz
                if line.strip() == "* hard core 0":
                    modified = True
                    continue
                
                new_lines.append(line)

            if modified:
                logger.info(f"[DEFAULT] '{limits_path}' dosyasından core dump kuralı kaldırılıyor...")
                temp_path = "/tmp/limits.conf.revert"
                with open(temp_path, "w") as f:
                    f.writelines(new_lines)
                success, output = run_command(['sudo', 'mv', temp_path, limits_path])
                if not success:
                    logger.error(f"[DEFAULT] '{limits_path}' geri alınamadı: {output}")
                    return
                logger.info(f"[DEFAULT] '{limits_path}' başarıyla temizlendi.")
            else:
                logger.info(f"[DEFAULT] '{limits_path}' içinde core dump kuralı bulunamadı.")

        except Exception as e:
            logger.error(f"[DEFAULT] '{limits_path}' geri alınırken hata: {e}")
