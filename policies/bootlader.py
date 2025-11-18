import os
import subprocess
from datetime import datetime
from logger import logger
from utils import get_logged_in_user, get_desktop_env, run_command
import stat

# ==============================================================================
# == BOOTLOADER (ÖNYÜKLEYİCİ) GÜVENLİĞİ POLİTİKALARI ===========================
# ==============================================================================

# Politika 1: Bootloader Parolasını Zorunlu Kıl
def enforce_bootloader_password(username, parameters):
    """
    GRUB önyükleyicisine parola koruması eklenip eklenmediğini kontrol eder.
    Eğer parola yoksa, parametrelerde belirtilen kullanıcı ve parola özeti (hash)
    ile yeni bir yapılandırma dosyası oluşturur.
    """
    grub_cfg_path = "/boot/grub/grub.cfg"
    
    try:
        if not os.path.exists(grub_cfg_path):
            return False, f"{grub_cfg_path} bulunamadı."

        with open(grub_cfg_path, "r") as f:
            content = f.read()

        # grub.cfg içinde parola ayarlanmış mı diye kontrol et
        if "password_pbkdf2" in content and "set superusers" in content:
            return True, "GRUB parolası zaten ayarlanmış görünüyor."
        else:
            return apply_bootloader_password(parameters)

    except Exception as e:
        return False, f"Bootloader parola kontrolünde hata: {e}"

def apply_bootloader_password(parameters):
    """
    Parametrelerde verilen kullanıcı adı ve parola özeti (hash) ile
    /etc/grub.d/ içinde yeni bir yetkilendirme dosyası oluşturur ve GRUB'u günceller.
    """
    grub_user = parameters.get("grub_user")
    password_hash = parameters.get("password_hash")

    if not grub_user or not password_hash:
        return False, "Politika hatası: 'grub_user' ve 'password_hash' parametreleri zorunludur."
    
    # GRUB parola hash'inin doğru formatta olup olmadığını basitçe kontrol edelim
    if not password_hash.startswith("grub.pbkdf2.sha512."):
        return False, "Politika hatası: 'password_hash' geçerli bir GRUB PBKDF2 özeti değil."

    auth_file_path = "/etc/grub.d/01_security"
    temp_path = "/tmp/01_security.new"
    
    # Yetkilendirme dosyasının içeriğini oluştur
    content = f"""
#!/bin/sh
cat <<EOF
set superusers="{grub_user}"
password_pbkdf2 {grub_user} {password_hash}
EOF
"""
    try:
        with open(temp_path, "w") as f:
            f.write(content)
        
        # Dosyayı sudo ile taşı
        success, output = run_command(['sudo', 'mv', temp_path, auth_file_path])
        if not success:
            return False, f"Yetkilendirme dosyası oluşturulamadı: {output}"
        # Dosyayı çalıştırılabilir yap
        success, output = run_command(['sudo', 'chmod', '+x', auth_file_path])
        if not success:
            return False, f"Yetkilendirme dosyası çalıştırılabilir yapılamadı: {output}"
        
        linux_config_path = "/etc/grub.d/10_linux"
        sed_cmd = [
            'sudo', 'sed', '-i',
            '/CLASS=.*--unrestricted.*/!s/CLASS="\\(.*\\)"/CLASS="\\1 --unrestricted"/',
            linux_config_path
        ]
        print(f"GRUB: {linux_config_path} dosyasına --unrestricted bayrağı ekleniyor...")
        success, output = run_command(sed_cmd)
        if not success:
            return False, f"--unrestricted bayrağı {linux_config_path} dosyasına eklenirken hata: {output}"
        # GRUB'u güncelle
        success, output = run_command(['sudo', 'update-grub'])
        if not success:
            return False, f"GRUB güncellenemedi: {output}"

        return True, "GRUB parolası başarıyla ayarlandı ve GRUB güncellendi. Yeniden başlatma sonrası aktif olacaktır."

    except subprocess.CalledProcessError as e:
        return False, f"sudo veya GRUB komutlarında hata: {e}. 'sudoers' dosyasını kontrol edin."
    except Exception as e:
        return False, f"Bootloader parolası uygulanırken hata: {e}"

#--------------------------------------------------------------------
# --------Grub paswordu disable etme politkası ---------------------------------

def apply_disable_grub_password(username, parameters):
    """
    CIS politikası tarafından ayarlanmış olan GRUB parolasını
    kaldırır. Bu işlem, /etc/grub.d/01_security dosyasını siler,
    10_linux dosyasındaki '--unrestricted' bayrağını temizler
    ve 'update-grub' komutunu çalıştırır.

    UYARI: Bu, GRUB yapılandırmasını değiştiren riskli bir işlemdir.
    """
    logger.info("[POLICY] GRUB parolası devre dışı bırakılıyor...")
    
    auth_file_path = "/etc/grub.d/01_security"
    linux_config_path = "/etc/grub.d/10_linux"
    
    changes_made = False

    # 'apply' tarafından oluşturulan parola dosyasını sil
    try:
        if os.path.exists(auth_file_path):
            logger.info(f"[POLICY] GRUB parola dosyası '{auth_file_path}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', auth_file_path])
            if success:
                changes_made = True
            else:
                logger.error(f"[POLICY] '{auth_file_path}' silinirken hata: {output}")
        else:
             logger.info(f"[POLICY] GRUB parola dosyası '{auth_file_path}' zaten yok.")
    except Exception as e:
        logger.error(f"[POLICY] '{auth_file_path}' silinirken istisna: {e}")

    # 'apply' tarafından 10_linux'e eklenen '--unrestricted' bayrağını kaldır
    try:
        if os.path.exists(linux_config_path):
            logger.info(f"[POLICY] '{linux_config_path}' dosyasından '--unrestricted' bayrağı temizleniyor...")
    
            sed_revert_cmd = [
                'sudo', 'sed', '-i',
                's/ --unrestricted//g',
                linux_config_path
            ]
            
            success, output = run_command(sed_revert_cmd)
            if success:
                changes_made = True 
            else:
                logger.error(f"[POLICY] '{linux_config_path}' temizlenirken hata: {output}")
        
        else:
            logger.warning(f"[POLICY] '{linux_config_path}' bulunamadı, --unrestricted temizlenemedi.")

    except Exception as e:
        logger.error(f"[POLICY] '{linux_config_path}' revert edilirken istisna: {e}")

    # 3. Eğer 1. veya 2. adımda bir değişiklik yapıldıysa 'update-grub' çalıştır
    if changes_made:
        try:
            logger.info("[POLICY] GRUB yapılandırması yeniden oluşturuluyor (update-grub)...")
            success, output = run_command(['sudo', 'update-grub'])
            if not success:
                error_msg = f"'update-grub' çalıştırılırken hata: {output}"
                logger.error(f"[POLICY] {error_msg}")
                return False, error_msg
            else:
                logger.info("[POLICY] 'update-grub' başarıyla tamamlandı.")
        except Exception as e:
            error_msg = f"'update-grub' çalıştırılırken istisna: {e}"
            logger.error(f"[POLICY] {error_msg}")
            return False, error_msg
            
    success_msg = "GRUB parolasını devre dışı bırakma işlemi tamamlandı."
    logger.info(f"[POLICY] {success_msg}")
    return True, success_msg
# --------------------------------------------------------------------------------

#  Bootloader Yapılandırma İzinlerini Sıkılaştır
def harden_bootloader_permissions(username, parameters):
    """
    grub.cfg dosyasının sahibinin root:root ve izinlerinin 600 (rw-------) olmasını sağlar.
    """
    try:
        grub_cfg_path = _find_grub_cfg_path()
        if not grub_cfg_path:
            return False, "grub.cfg dosyası /boot/grub/ veya /boot/grub2/ içinde bulunamadı."

        file_stat = os.stat(grub_cfg_path)
        current_perms = stat.S_IMODE(file_stat.st_mode)
        current_uid = file_stat.st_uid
        current_gid = file_stat.st_gid

        # İstenen durum: sahip=root(0), grup=root(0), izinler=600 (octal 0o600)
        is_secure = (current_uid == 0 and current_gid == 0 and current_perms == 0o600)

        if is_secure:
            return True, f"grub.cfg dosya izinleri ({oct(current_perms)[2:]} root:root) zaten güvenli."
        else:
            return apply_bootloader_permissions(grub_cfg_path)

    except Exception as e:
        return False, f"Bootloader izinleri kontrol edilirken hata: {e}"

def apply_bootloader_permissions(path: str):
    """
    Belirtilen dosyanın sahibini root:root ve izinlerini 600 olarak ayarlar.
    """
    try:
        # Sahibi root:root yap
        success, output = run_command(['sudo', 'chown', 'root:root', path])
        if not success:
            return False, f"Dosya sahibi değiştirilemedi: {output}"
        # İzinleri 600 (sadece root okur/yazar) yap
        success, output = run_command(['sudo', 'chmod', '600', path])
        if not success:
            return False, f"Dosya izinleri değiştirilemedi: {output}"
        return True, f"{path} dosyasının sahibi root:root ve izinleri 600 olarak ayarlandı."
    except Exception as e:
        return False, f"Bootloader izinleri uygulanırken hata: {e}"

def _find_grub_cfg_path():
    """grub.cfg dosyasının yaygın konumlarını arar."""
    common_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    for path in common_paths:
        if os.path.exists(path):
            return path
    return None

    