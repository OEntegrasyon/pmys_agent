import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

FSTAB_OPTIONS_TO_REVERT = [
    "nodev",
    "nosuid",
    "noexec"
]

def revert_fstab_changes():
    """
    /etc/fstab dosyasında CIS politikaları tarafından yapılmış olan değişiklikleri
    (tmpfs eklemesi, mount seçenekleri) geri alır.
    """
    fstab_path = "/etc/fstab"
    logger.info("[DEFAULT] /etc/fstab yapılandırması kontrol ediliyor...")

    if not os.path.exists(fstab_path):
        logger.warning(f"[DEFAULT] {fstab_path} bulunamadı, kontrol atlanıyor.")
        return

    try:
        with open(fstab_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        modified = False

        for line in lines:
            original_line = line
            # 1. /tmp için tmpfs satırını bul ve sil
            if "/tmp tmpfs" in line and "# PMYS Agent tarafindan eklendi" in lines[lines.index(line)-1]:
                logger.info("[DEFAULT] /tmp için eklenen tmpfs satırı kaldırılıyor...")
                modified = True
                # Yorum satırını da atlamak için bir önceki satırı da kontrol et
                if new_lines and "# PMYS Agent tarafindan eklendi" in new_lines[-1]:
                    new_lines.pop() # Yorum satırını listeden çıkar
                continue # tmpfs satırını yeni listeye ekleme

            # 2. Mount seçeneklerini (nodev, nosuid, noexec) temizle
            # Yorum satırı değilse veya boş değilse
            if not line.strip().startswith('#') and line.strip():
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    options = parts[3]
                    original_options = options
                    for option_to_remove in FSTAB_OPTIONS_TO_REVERT:
                        # Seçenekleri virgülle ayır, kaldır ve tekrar birleştir
                        opts_list = options.split(',')
                        if option_to_remove in opts_list:
                            opts_list.remove(option_to_remove)
                            options = ",".join(opts_list)
                    
                    if original_options != options:
                        logger.info(f"[DEFAULT] '{parts[1]}' mount noktası için seçenekler temizleniyor: {original_options} -> {options}")
                        parts[3] = options
                        line = " ".join(parts) + "\n"
                        modified = True
            
            new_lines.append(line)

        # Eğer herhangi bir değişiklik yapıldıysa, fstab dosyasını yeniden yaz
        if modified:
            logger.info(f"[DEFAULT] /etc/fstab dosyası varsayılana döndürülüyor...")
            temp_path = "/tmp/fstab.revert"
            with open(temp_path, "w") as f:
                f.writelines(new_lines)
            
            success, output = run_command(['sudo', 'mv', temp_path, fstab_path])
            if not success:
                logger.error(f"[DEFAULT] /etc/fstab geri alınamadı: {output}")
                return
            # Değişikliklerin anında geçerli olması için sistemi yeniden mount etmeyi dene
            success, output = run_command(['sudo', 'mount', '-a']) # Hata verirse bile devam etsin
            if not success:
                logger.error(f"[DEFAULT] /etc/fstab yeniden mount edilirken hata: {output}")
            logger.info("[DEFAULT] /etc/fstab başarıyla varsayılana döndürüldü.")
        else:
            logger.info("[DEFAULT] /etc/fstab zaten varsayılan durumda.")

    except Exception as e:
        logger.error(f"[DEFAULT] /etc/fstab geri alınırken hata: {e}")