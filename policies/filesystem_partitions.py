import os
import re
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command

# ==============================================================================
# == AYRI PARTİSYON KONTROL POLİTİKALARI ========================================
# ==============================================================================

# --- /tmp için Otomatik Düzeltmeli Politika ---

def check_tmp_is_separate_partition(username, parameters):
    """
    /tmp dizininin ayrı bir bölümde olup olmadığını kontrol eder.
    Eğer değilse, otomatik olarak tmpfs çözümünü uygular.
    """
    try:
        if os.stat('/tmp').st_dev != os.stat('/').st_dev:
            return True, "/tmp dizini, kök dizininden ayrı bir bölümde bulunuyor."
        else:
            return apply_tmp_as_tmpfs()
    except Exception as e:
        return False, f"/tmp partisyonu kontrol edilirken hata oluştu: {e}"

def apply_tmp_as_tmpfs():
    """
    /tmp dizinini RAM üzerinde çalışan bir tmpfs olarak yapılandırır.
    Bu işlem /etc/fstab dosyasını düzenler ve sudo yetkisi gerektirir.
    """
    fstab_path = "/etc/fstab"
    backup_path = f"/etc/fstab.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    tmpfs_line = "\n# PMYS Agent tarafindan eklendi: /tmp icin tmpfs\ntmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,size=2G 0 0\n"
    try:
        subprocess.run(['sudo', 'cp', fstab_path, backup_path], check=True)
        subprocess.run(f"sudo sh -c 'echo \"{tmpfs_line}\" >> {fstab_path}'", shell=True, check=True)
        subprocess.run(['sudo', 'mount', '-a'], check=True)
        return True, "/tmp ayrı bir bölümde değildi. tmpfs olarak başarıyla yapılandırıldı ve aktif edildi."
    except Exception as e:
        return False, f"tmpfs uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."


# --- /var ve /home için Sadece Kontrol Yapan Politikalar (Apply Fonksiyonu Yok) ---

def check_var_is_separate_partition(username, parameters):
    """
    /var dizininin ayrı bir bölümde olup olmadığını KONTROL EDER. 
    Uygulama (apply) yapmaz, sadece raporlar.
    """
    try:
        if os.stat('/var').st_dev != os.stat('/').st_dev:
            return True, f"Uyumlu: /var dizini ayrı bir bölümde."
        else:
            return False, f"Uyumsuz: /var dizini ayrı bir bölümde değil. Manuel müdahale gereklidir."
    except Exception as e:
        return False, f"/var kontrol edilirken hata: {e}"

def check_home_is_separate_partition(username, parameters):
    """
    /home dizininin ayrı bir bölümde olup olmadığını KONTROL EDER.
    Uygulama (apply) yapmaz, sadece raporlar.
    """
    try:
        if os.stat('/home').st_dev != os.stat('/').st_dev:
            return True, f"Uyumlu: /home dizini ayrı bir bölümde."
        else:
            return False, f"Uyumsuz: /home dizini ayrı bir bölümde değil. Manuel müdahale gereklidir."
    except Exception as e:
        return False, f"/home kontrol edilirken hata: {e}"


# ==============================================================================
# == GENEL MOUNT SEÇENEĞİ POLİTİKASI (PARAMETRELİ) =============================
# ==============================================================================

def enforce_mount_option(username, parameters):
    """
    Belirtilen bir bağlama noktasına (mount point) istenen güvenlik seçeneğinin
    (nodev, nosuid, noexec) eklenmesini sağlar ve zorunlu kılar.
    """
    mount_point = parameters.get("mount_point")
    mount_option = parameters.get("mount_option")
    if not mount_point or not mount_option:
        return False, "Politika hatası: 'mount_point' ve 'mount_option' parametreleri zorunludur."
    try:
        result = subprocess.run(['findmnt', '-n', '-o', 'OPTIONS', '--target', mount_point], capture_output=True, text=True)
        current_options = result.stdout.strip()
        if mount_option in current_options.split(','):
            return True, f"'{mount_point}' için '{mount_option}' seçeneği zaten aktif."
        else:
            return apply_mount_option(mount_point, mount_option)
    except Exception as e:
        return False, f"Mount seçeneği kontrolünde hata: {e}"


def apply_mount_option(mount_point: str, mount_option: str) -> tuple[bool, str]:
    """
    /etc/fstab dosyasını düzenleyerek belirtilen bağlama noktasına
    istenen seçeneği ekler ve sistemi yeniden mount eder.
    """
    fstab_path = "/etc/fstab"
    temp_path = "/tmp/fstab.new"
    try:
        if not os.path.exists(fstab_path): return False, f"{fstab_path} dosyası bulunamadı."
        with open(fstab_path, "r") as f: lines = f.readlines()

        found_line, modified = False, False
        new_lines = []
        for line in lines:
            if line.strip().startswith('#') or not line.strip():
                new_lines.append(line); continue
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 4 and parts[1] == mount_point:
                found_line = True
                options = parts[3].split(',')
                if mount_option not in options:
                    options.append(mount_option)
                    parts[3] = ",".join(options)
                    new_lines.append(" ".join(parts) + "\n")
                    modified = True
                else: new_lines.append(line)
            else: new_lines.append(line)

        if not found_line: return False, f"'{mount_point}' için {fstab_path} içinde bir girdi bulunamadı."
        if not modified: return True, "Değişiklik yapılmadı, seçenek zaten mevcuttu."

        with open(temp_path, "w") as f: f.writelines(new_lines)

        backup_path = f"/etc/fstab.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        subprocess.run(['sudo', 'cp', fstab_path, backup_path], check=True)
        subprocess.run(['sudo', 'mv', temp_path, fstab_path], check=True)
        subprocess.run(['sudo', 'mount', '-o', 'remount', mount_point], check=True)

        return True, f"'{mount_point}' için '{mount_option}' seçeneği başarıyla eklendi ve sistem yeniden mount edildi."
    except Exception as e:
        return False, f"fstab düzenlenirken hata oluştu: {e}. sudoers dosyasını kontrol edin."

