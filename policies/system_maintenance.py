import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
import stat
import pwd
import grp

# ==============================================================================
# == DOSYA İZİN VE SAHİPLİK POLİTİKASI (PARAMETRELİ) ==========================
# ==============================================================================

def enforce_file_permissions(username, parameters):
    """
    Parametre olarak belirtilen bir dosyanın sahip, grup ve dosya izinlerinin
    belirtilen değerlerle eşleşip eşleşmediğini kontrol eder. Eşleşmiyorsa düzeltir.
    'group' parametresi virgülle ayrılmış çoklu değerleri kabul eder (örn: "root,shadow").
    'permissions' "veya daha kısıtlayıcı" (örn: 644) kontrolü yapar.
    """
    file_path = parameters.get("file_path")
    expected_owner_name = parameters.get("owner")
    expected_group_names = parameters.get("group") 
    expected_perms_str = parameters.get("permissions") 

    if not all([file_path, expected_owner_name, expected_group_names, expected_perms_str]):
        return False, "Politika hatası: 'file_path', 'owner', 'group', ve 'permissions' parametreleri zorunludur."

    try:
        if not os.path.exists(file_path):
            return False, f"Kontrol edilecek dosya bulunamadı: {file_path}"

        file_stat = os.stat(file_path)
        
        # --- 1. Sahiplik Kontrolü ---
        current_uid = file_stat.st_uid
        expected_uid = pwd.getpwnam(expected_owner_name).pw_uid
        owner_ok = (current_uid == expected_uid)

        # --- 2. Grup Kontrolü ---
        current_gid = file_stat.st_gid
        current_group_name = grp.getgrgid(current_gid).gr_name
        
        allowed_groups = expected_group_names.split(',')
        group_ok = (current_group_name in allowed_groups)

        # --- 3. İzin Kontrolü ---
        # İzinler "beklenen" (örn: 644) VEYA "daha kısıtlayıcı" (örn: 640, 600) olmalı
        current_perms_oct = stat.S_IMODE(file_stat.st_mode)
        expected_perms_oct = int(expected_perms_str, 8)
        unexpected_permissions = current_perms_oct & ~expected_perms_oct
        perms_ok = (unexpected_permissions == 0)
        
        # 'shadow' için özel durum: 640 beklenirken 600 (daha kısıtlayıcı) gelirse
        if expected_perms_str == "640" and current_perms_oct == 0o600:
            perms_ok = True
        # 'passwd' için özel durum: 644 beklenirken 640 veya 600 gelirse
        if expected_perms_str == "644" and (current_perms_oct == 0o640 or current_perms_oct == 0o600):
            perms_ok = True

        # Tüm kontroller doğru mu
        if owner_ok and group_ok and perms_ok:
            return True, f"'{file_path}' için sahiplik ve izinler zaten doğru."
        else:
            return apply_file_permissions(parameters)

    except (KeyError, ValueError) as e:
        return False, f"Geçersiz kullanıcı/grup adı: {e}"
    except Exception as e:
        return False, f"Dosya izinleri kontrol edilirken hata: {e}"

def apply_file_permissions(parameters):
    """
    Belirtilen dosyanın sahibini, grubunu ve izinlerini ayarlar.
    'group' parametresi "root,shadow" gibi bir liste ise, İLK olanı (tercih edileni) ayarlar.
    """
    file_path = parameters.get("file_path")
    owner = parameters.get("owner")
    group_list = parameters.get("group")
    permissions = parameters.get("permissions")

    try:
        # Düzeltme için listenin ilk elemanını (tercih edileni) kullan
        preferred_group = group_list.split(',')[0]
        
        # Sahip ve grubu tek komutta ayarla
        success, output = run_command(['sudo', 'chown', f'{owner}:{preferred_group}', file_path])
        if not success:
            return False, f"Sahip ve grup ayarlanırken hata: {output}."

        # İzinleri ayarla
        success, output = run_command(['sudo', 'chmod', permissions, file_path])
        if not success:
            return False, f"İzinler ayarlanırken hata: {output}."

        return True, f"'{file_path}' için sahiplik ({owner}:{preferred_group}) ve izinler ({permissions}) başarıyla ayarlandı."
    
    except Exception as e:
        return False, f"Dosya izinleri uygulanırken genel hata: {e}"
# ==============================================================================
# == DOSYA İZİN VE SAHİPLİK POLİTİKALARI =======================================
# ==============================================================================

# CIS 7.1.11: Herkese Yazma İzni Olan Dosya ve Dizinleri Güvenli Hale Getir
def secure_world_writable_files_and_dirs(username, parameters):
    """
    Sistemde herkese yazma izni olan dosyaları VE 'sticky bit'i olmayan dizinleri
    tespit eder. Bulunursa, izinleri düzeltmek için 'apply' fonksiyonunu çağırır.
    """
    try:
        # Bu, /proc, /sys ve geçici dizinlerdeki aramaları engeller.
        exclude_paths = [
            "/proc", "/sys", "/run", "/snap", "/tmp", "/var/tmp"
        ]
        
        # 'find' komutu için -path ... -prune argümanları oluştur
        prune_args = []
        for path in exclude_paths:
            prune_args.extend(['-path', path, '-o'])
        prune_args.pop()
        prune_args = ['('] + prune_args + [')', '-prune']

        find_files_cmd = ['find', '/', '-xdev'] + prune_args + ['-o', '-type', 'f', '-perm', '-0002', '-print']
            
        proc_files = subprocess.run(find_files_cmd, capture_output=True, text=True, check=False)
        if proc_files.returncode > 0: 
             if "Permission denied" not in proc_files.stderr and proc_files.stderr:
                return False, f"World-writable dosyalar aranırken hata: {proc_files.stderr}"
        
        files_to_fix = proc_files.stdout.strip().splitlines()

        find_dirs_cmd = ['find', '/', '-xdev'] + prune_args + ['-o', '-type', 'd', '-perm', '-0002', '!', '-perm', '-1000', '-print']
        
        proc_dirs = subprocess.run(find_dirs_cmd, capture_output=True, text=True, check=False)
        if proc_dirs.returncode > 0:
             if "Permission denied" not in proc_dirs.stderr and proc_dirs.stderr:
                return False, f"World-writable dizinler aranırken hata: {proc_dirs.stderr}"

        dirs_to_fix = proc_dirs.stdout.strip().splitlines()

        if not files_to_fix and not dirs_to_fix:
            return True, "Uyumlu: Güvenli olmayan 'world-writable' dosya veya dizin bulunmadı."
        else:
            return apply_secure_world_writable_permissions(files_to_fix, dirs_to_fix)
            
    except Exception as e:
        return False, f"World-writable öğeler kontrol edilirken hata: {e}"
    
def apply_secure_world_writable_permissions(files_to_fix: list, dirs_to_fix: list):
    """
    Dosyalardan herkese yazma iznini kaldırır, dizinlere ise 'sticky bit' ekler.
    """
    messages = []
    errors = []
    try:
        # Dosyaların 'other' yazma iznini kaldır (chmod o-w)
        if files_to_fix:
            for file_path in files_to_fix:
                success, output = run_command(['sudo', 'chmod', 'o-w', file_path])
                if not success:
                    errors.append(f"{file_path}: {output}")
            messages.append(f"{len(files_to_fix)} adet dosyanın herkese yazma izni kaldırıldı.")

        # Dizinlere sticky bit ekle (chmod a+t)
        if dirs_to_fix:
            for dir_path in dirs_to_fix:
                success, output = run_command(['sudo', 'chmod', 'a+t', dir_path])
                if not success:
                    errors.append(f"{dir_path}: {output}")
            messages.append(f"{len(dirs_to_fix)} adet dizine 'sticky bit' eklendi.")

        return True, " ".join(messages)
   
    except Exception as e:
        return False, f"İzinler uygulanırken genel hata: {e}"

#====================================================================================
def audit_and_fix_unowned_files(username, parameters):
    """
    Sistemde geçerli bir sahibi veya grubu olmayan dosyaları ve dizinleri
    tespit eder. CIS raporuna uygun olarak /proc, /sys vb. hariç tutulur.
    Parametrelerde bir 'action' belirtilmişse, düzeltme uygular.
    """
    try:
        # CIS raporundaki hariç tutulan yollar 
        exclude_paths = [
            "/proc", "/sys", "/run", "/snap", "/dev", "/home"
        ]
        prune_args = []
        for path in exclude_paths:
            prune_args.extend(['-path', path, '-o'])
        prune_args.pop()
        prune_args = ['('] + prune_args + [')', '-prune']

        # 'find / -xdev ( ... -prune ) -o ( -nouser -o -nogroup ) -print'
        find_cmd = ['find', '/', '-xdev'] + prune_args + ['-o', '(', '-nouser', '-o', '-nogroup', ')', '-print']
        
        proc = subprocess.run(find_cmd, capture_output=True, text=True, check=False)
        if proc.returncode > 0:
             if "Permission denied" not in proc.stderr and proc.stderr:
                return False, f"Sahipsiz dosyalar aranırken hata: {proc.stderr}"

        unowned_files = proc.stdout.strip().splitlines()

        if not unowned_files:
            return True, "Uyumlu: Sistemde sahibi veya grubu olmayan dosya bulunmuyor."

        action = parameters.get("action")
        if action in ["chown", "delete"]:
            return apply_fix_unowned_files(unowned_files, parameters)
        else:
            file_list_str = ", ".join(unowned_files[:5])
            if len(unowned_files) > 5:
                file_list_str += f" ve {len(unowned_files) - 5} diğer dosya..."
            return False, f"Uyumsuz: Sahipsiz dosyalar tespit edildi (örn: {file_list_str}). Düzeltme için 'action' parametresi ('chown' veya 'delete') belirtilmemiş."

    except Exception as e:
        return False, f"Sahipsiz dosya kontrolünde hata: {e}"

def apply_fix_unowned_files(file_list: list, parameters: dict):
    """
    Bulunan sahipsiz dosyalara, parametrelerde belirtilen eylemi uygular.
    "No such file" (Yarış Durumu) hatalarını görmezden gelir.
    """
    action = parameters.get("action")
    errors = [] 
    
    try:
        if action == "chown":
            new_owner = parameters.get("new_owner", "root")
            new_group = parameters.get("new_group", "root")
            
            for file_path in file_list:
                success, output = run_command(['sudo', 'chown', f'{new_owner}:{new_group}', file_path])
                
                if not success:
                    if "Böyle bir dosya ya da dizin yok" in output or "No such file or directory" in output:
                        print(f"Bilgi: '{file_path}' sahipsizdi ancak işlem sırasında silindi (Yarış Durumu).")
                    else:
                        errors.append(f"{file_path}: {output}")
            
            if errors:
                return False, f"Bazı sahipsiz dosyaların sahibi değiştirilemedi: {', '.join(errors)}"
            
            return True, f"{len(file_list)} adet sahipsiz dosya denetlendi, {len(errors)} hata dışında kalanlar '{new_owner}:{new_group}' olarak ayarlandı."

        elif action == "delete":
            for file_path in file_list:
                success, output = run_command(['sudo', 'rm', '-rf', file_path])
                
                if not success:
                    if "Böyle bir dosya ya da dizin yok" in output or "No such file or directory" in output:
                        print(f"Bilgi: '{file_path}' sahipsizdi ancak işlem sırasında silindi (Yarış Durumu).")
                    else:
                        errors.append(f"{file_path}: {output}")
            
            if errors:
                return False, f"Bazı sahipsiz dosyalar silinemedi: {', '.join(errors)}"
                
            return True, f"DİKKAT: {len(file_list)} adet sahipsiz dosya denetlendi, {len(errors)} hata dışında kalanlar sistemden silindi."

        else:
            return False, f"Geçersiz eylem belirtildi: {action}. Sadece 'chown' veya 'delete' kullanılabilir."

    except Exception as e:
        return False, f"Eylem '{action}' uygulanırken genel hata: {e}"
# ==============================================================================

# Paylaşılan dizinlerin izinleri

def check_shared_directory_permissions(username, parameters):
    directory = parameters.get('directory')
    expected_owner = parameters.get('owner')
    expected_group = parameters.get('group')
    expected_permissions = parameters.get('permissions') 

    if not directory or not expected_owner or not expected_group or not expected_permissions:
        return False, "Eksik parametre: directory, owner, group ve permissions gerekli."

    try:
        # Mevcut izin ve sahiplik kontrolü
        stat_info = os.stat(directory)
        current_owner = subprocess.getoutput(f'stat -c %U {directory}')
        current_group = subprocess.getoutput(f'stat -c %G {directory}')
        current_permissions = oct(stat_info.st_mode)[-3:]

        if (current_owner != expected_owner or
            current_group != expected_group or
            current_permissions != expected_permissions):           
            return apply_shared_directory_permissions(parameters)
        else:
            return True, "Dizin sahipliği ve izinler zaten doğru ayarlanmış."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def apply_shared_directory_permissions(parameters):
    directory = parameters.get('directory')
    expected_owner = parameters.get('owner')
    expected_group = parameters.get('group')
    expected_permissions = parameters.get('permissions')  # Örn: '770'

    try:
        # Sahip ve grup değiştirme
        subprocess.run(['chown', f'{expected_owner}:{expected_group}', directory], check=True)
        # İzinleri değiştirme
        subprocess.run(['chmod', expected_permissions, directory], check=True)

        return True, "Dizin sahipliği ve izinler başarıyla güncellendi."

    except subprocess.CalledProcessError as e:
        return False, f"Komut hatası: {str(e)}"
    except Exception as e:
        return False, f"Hata: {str(e)}"
# ==============================================================================