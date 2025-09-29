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
    """
    # Bu politika kullanıcıya özel değil, sistem geneli olduğu için 'username' kullanılmaz.
    
    file_path = parameters.get("file_path")
    expected_owner_name = parameters.get("owner")
    expected_group_name = parameters.get("group")
    expected_perms_str = parameters.get("permissions") # Örn: "644"

    if not all([file_path, expected_owner_name, expected_group_name, expected_perms_str]):
        return False, "Politika hatası: 'file_path', 'owner', 'group', ve 'permissions' parametreleri zorunludur."

    try:
        if not os.path.exists(file_path):
            return False, f"Kontrol edilecek dosya bulunamadı: {file_path}"

        # Mevcut dosya bilgilerini al
        file_stat = os.stat(file_path)
        
        # Sahiplik kontrolü (isimleri ID'ye çevirerek)
        current_uid = file_stat.st_uid
        current_gid = file_stat.st_gid
        expected_uid = pwd.getpwnam(expected_owner_name).pw_uid
        expected_gid = grp.getgrnam(expected_group_name).gr_gid
        
        # İzin kontrolü (metni octal sayıya çevirerek)
        current_perms_oct = stat.S_IMODE(file_stat.st_mode)
        expected_perms_oct = int(expected_perms_str, 8) # '644' -> 0o644

        # Tüm kontroller doğru mu?
        if current_uid == expected_uid and current_gid == expected_gid and current_perms_oct == expected_perms_oct:
            return True, f"'{file_path}' için sahiplik ve izinler zaten doğru."
        else:
            # Bir veya daha fazlası yanlışsa, düzeltmek için apply fonksiyonunu çağır
            return apply_file_permissions(parameters)

    except (KeyError, ValueError):
        return False, f"Geçersiz kullanıcı '{expected_owner_name}' veya grup '{expected_group_name}' adı."
    except Exception as e:
        return False, f"Dosya izinleri kontrol edilirken hata: {e}"


def apply_file_permissions(parameters):
    """
    Belirtilen dosyanın sahibini, grubunu ve izinlerini ayarlar.
    """
    file_path = parameters.get("file_path")
    owner = parameters.get("owner")
    group = parameters.get("group")
    permissions = parameters.get("permissions")

    try:
        # Sahip ve grubu tek komutta ayarla
        success, output = run_command(['sudo', 'chown', f'{owner}:{group}', file_path])
        if not success:
            return False, f"Sahip ve grup ayarlanırken hata: {output}. 'sudoers' dosyasını kontrol edin."

        # İzinleri ayarla
        success, output = run_command(['sudo', 'chmod', permissions, file_path])
        if not success:
            return False, f"İzinler ayarlanırken hata: {output}. 'sudoers' dosyasını kontrol edin."

        return True, f"'{file_path}' için sahiplik ve izinler başarıyla ayarlandı."
  
    except Exception as e:
        return False, f"Dosya izinleri uygulanırken genel hata: {e}"


# ==============================================================================
# == DOSYA İZİN VE SAHİPLİK POLİTİKALARI =======================================
# ==============================================================================

# CIS 7.1.11: Herkese Yazma İzni Olan Dosya ve Dizinleri Güvenli Hale Getir
def secure_world_writable_files_and_dirs(username, parameters):
    """
    Sistemde herkese yazma izni olan dosyaları ve 'sticky bit'i olmayan dizinleri
    tespit eder. Bulunursa, izinleri düzeltmek için 'apply' fonksiyonunu çağırır.
    """
    # Bu politika parametre gerektirmez.
    try:
        # Önce herkese yazma izni olan (-perm -0002) tüm dosya ve dizinleri bulalım
        find_cmd = ['find', '/', '-xdev', '-type', 'f', '-perm', '-0002', '-not', '-path', '/etc/mtab', '-print']
        success, output = run_command(find_cmd)
        if not success:
            return False, f"World-writable dosyalar bulunurken hata: {output}"

        all_ww_items = output.strip().splitlines()

        if not all_ww_items:
            return True, "Sistemde herkese yazma izni olan dosya veya dizin bulunmuyor."

        files_to_fix = []
        dirs_to_fix = []

        for item_path in all_ww_items:
            if os.path.isfile(item_path):
                files_to_fix.append(item_path)
            elif os.path.isdir(item_path):
                # Dizinler için 'sticky bit' kontrolü yap
                # Sticky bit (0o1000), bir dizindeki dosyaların sadece sahibi tarafından silinmesini sağlar.
                if not (os.stat(item_path).st_mode & stat.S_ISVTX):
                    dirs_to_fix.append(item_path)

        if not files_to_fix and not dirs_to_fix:
            return True, "Tüm 'world-writable' dizinlerde sticky bit ayarlı, sorun yok."
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
    tespit eder. Parametrelerde bir 'action' belirtilmişse, düzeltme uygular.
    """
    try:
        find_cmd = ['find', '/', '-xdev', '-nouser', '-o', '-nogroup', '-print']
        success, output = run_command(find_cmd)
        if not success:
            return False, f"Sahipsiz dosyalar bulunurken hata: {output}"

        unowned_files = output.strip().splitlines()

        if not unowned_files:
            return True, "Uyumlu: Sistemde sahibi veya grubu olmayan dosya bulunmuyor."

        # Eğer sahipsiz dosya bulunduysa ve parametrelerde bir eylem belirtilmişse, uygula
        action = parameters.get("action")
        if action in ["chown", "delete"]:
            return apply_fix_unowned_files(unowned_files, parameters)
        else:
            # Eğer eylem belirtilmemişse, sadece raporla
            file_list_str = ", ".join(unowned_files[:5])
            if len(unowned_files) > 5:
                file_list_str += f" ve {len(unowned_files) - 5} diğer dosya..."
            return False, f"Uyumsuz: Sahipsiz dosyalar tespit edildi. Düzeltme için 'action' parametresi belirtilmemiş: {file_list_str}"

    except Exception as e:
        return False, f"Sahipsiz dosya kontrolünde hata: {e}"

def apply_fix_unowned_files(file_list: list, parameters: dict):
    """
    Bulunan sahipsiz dosyalara, parametrelerde belirtilen eylemi uygular.
    Eylemler: 'chown' veya 'delete'.
    """
    action = parameters.get("action")
    
    try:
        if action == "chown":
            new_owner = parameters.get("new_owner", "root") # Varsayılan: root
            new_group = parameters.get("new_group", "root") # Varsayılan: root
            
            for file_path in file_list:
                success, output = run_command(['sudo', 'chown', f'{new_owner}:{new_group}', file_path])
                if not success:
                    return False, f"Sahipsiz dosya sahibi değiştirilemedi: {output}. 'sudoers' dosyasını kontrol edin."
            
            return True, f"{len(file_list)} adet sahipsiz dosyanın sahibi başarıyla '{new_owner}:{new_group}' olarak değiştirildi."

        elif action == "delete":
            # BU İŞLEM GERİ ALINAMAZ, DİKKATLİ KULLANIN!
            for file_path in file_list:
                # Hem dosya hem de dizinleri silebilmek için -rf kullanıyoruz
                success, output = run_command(['sudo', 'rm', '-rf', file_path])
                if not success:
                    return False, f"Sahipsiz dosya silinemedi: {output}. 'sudoers' dosyasını kontrol edin."

            return True, f"DİKKAT: {len(file_list)} adet sahipsiz dosya sistemden kalıcı olarak silindi."

        else:
            return False, f"Geçersiz eylem belirtildi: {action}. Sadece 'chown' veya 'delete' kullanılabilir."

    except Exception as e:
        return False, f"Eylem '{action}' uygulanırken genel hata: {e}"