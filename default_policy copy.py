import os
import re
import stat
import subprocess
from logger import logger
from utils import run_command;

def restore_all_to_default():
    """
    Tüm politika modüllerindeki 'revert' fonksiyonlarını çağırarak
    sistemi varsayılan ayarlarına döndürür.
    """
    logger.info("="*50)
    logger.info("Sistem varsayılan ayarlara döndürülüyor...")
    logger.info("="*50)

    # Her bir geri alma fonksiyonunu sırayla ve güvenli bir şekilde çağır
    _revert_safely(revert_apparmor_in_bootloader, "AppArmor GRUB")
    _revert_safely(revert_login_banners, "Login Banners")
    _revert_safely(revert_bootloader_password, "Bootloader Password")
    _revert_safely(revert_bootloader_permissions, "Bootloader Permissions")
    _revert_safely(revert_package_removals, "Package Removals")
    _revert_safely(revert_disabled_modules, "Kernel Module Disabling")
    _revert_safely(revert_fstab_changes, "Fstab (Partition & Mount Options)")
    _revert_safely(revert_disabled_modules, "Kernel Module Disabling")
    _revert_safely(revert_interface_protocols, "Interface/Protocol Disabling")
    _revert_safely(revert_sysctl_parameters, "Sysctl Parameters")
    _revert_safely(revert_apt_and_update_settings, "APT & Update Settings")
    _revert_safely(revert_process_hardening, "Process Hardening")
    _revert_safely(revert_file_permissions_and_ownership, "File Permissions & Ownership")





    logger.info("="*50)
    logger.info("Varsayılan ayarlara döndürme işlemi tamamlandı.")
    logger.info("="*50)

def _revert_safely(revert_function, policy_name):
    """Hata olsa bile diğerlerinin çalışmasını sağlayan yardımcı fonksiyon"""
    try:
        revert_function()
    except Exception as e:
        logger.error(f"'{policy_name}' ayarları geri alınırken hata oluştu: {e}")


# === Geri Alma (Revert) Fonksiyonları ===

def revert_apparmor_in_bootloader():
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

#-------------------------------------------------------------------------------------

### 1. Login Banners (Giriş Başlıkları) Geri Alma ###

def revert_login_banners():
    """
    /etc/motd, /etc/issue ve /etc/issue.net dosyalarını silerek
    giriş başlıklarını varsayılan durumuna getirir.
    """
    banner_files = ["/etc/motd", "/etc/issue", "/etc/issue.net"]
    logger.info("[DEFAULT] Giriş başlıkları kontrol ediliyor...")

    for file_path in banner_files:
        # CIS politikası bu dosyayı oluşturmuş veya değiştirmiş mi diye kontrol et.
        if os.path.exists(file_path):
            try:
                # Pardus'un varsayılanında bu dosyalar genellikle boştur veya sadece
                # sistem bilgisi içerir. Güvenli varsayılan, bu dosyaları silmektir.
                logger.info(f"[DEFAULT] '{file_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', file_path])
                if not success:
                    logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {output}")
                    continue
                logger.info(f"[DEFAULT] '{file_path}' başarıyla varsayılana döndürüldü (kaldırıldı).")
            except Exception as e:
                logger.error(f"[DEFAULT] '{file_path}' kaldırılırken hata: {e}")
        else:
            logger.info(f"[DEFAULT] '{file_path}' zaten mevcut değil (varsayılan durum).")

### 2. Bootloader Password (Önyükleyici Parolası) Geri Alma ###

def revert_bootloader_password():
    """
    CIS politikasının GRUB parolası için oluşturduğu /etc/grub.d/01_security
    dosyasını kaldırır ve GRUB'u günceller.
    """
    auth_file_path = "/etc/grub.d/01_security"
    logger.info("[DEFAULT] GRUB parola yapılandırması kontrol ediliyor...")

    # CIS politikası bu dosyayı oluşturmuş mu diye kontrol et.
    if os.path.exists(auth_file_path):
        try:
            logger.info(f"[DEFAULT] GRUB parola dosyası '{auth_file_path}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', auth_file_path])
            if not success:
                logger.error(f"[DEFAULT] GRUB parola dosyası kaldırılırken hata: {output}")
                return
            # Değişikliğin geçerli olması için GRUB'u güncellem
            logger.info("[DEFAULT] GRUB yapılandırması güncelleniyor...")
            success, output = run_command(['sudo', 'update-grub'])
            if not success:
                logger.error(f"[DEFAULT] GRUB güncellenirken hata: {output}")
                return
            logger.info("[DEFAULT] GRUB parolası başarıyla kaldırıldı.")
        except Exception as e:
            logger.error(f"[DEFAULT] GRUB parolası geri alınırken hata: {e}")
    else:
        logger.info("[DEFAULT] GRUB parolası zaten ayarlı değil (varsayılan durum).")

### 3. Bootloader Permissions (Önyükleyici İzinleri) Geri Alma ###

def _find_grub_cfg_path():
    """grub.cfg dosyasının yaygın konumlarını arar."""
    common_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    for path in common_paths:
        if os.path.exists(path):
            return path
    return None

def revert_bootloader_permissions():
    """
    grub.cfg dosyasının izinlerini varsayılan olan '644'e geri döndürür.
    """
    logger.info("[DEFAULT] GRUB yapılandırma dosyası izinleri kontrol ediliyor...")
    grub_cfg_path = _find_grub_cfg_path()
    if not grub_cfg_path:
        logger.warning("[DEFAULT] grub.cfg dosyası bulunamadı, izin kontrolü atlanıyor.")
        return

    try:
        file_stat = os.stat(grub_cfg_path)
        # İzinleri octal (sekizlik) formatta al
        current_perms = oct(stat.S_IMODE(file_stat.st_mode))
        
        # Varsayılan izin '0o644' veya string olarak '0644'
        default_perms = '0o644'
        
        # Eğer izinler varsayılandan farklıysa (yani 600 yapılmışsa)
        if current_perms != default_perms:
            logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri ({current_perms}) varsayılana ({default_perms}) döndürülüyor...")
            success, output = run_command(['sudo', 'chmod', '644', grub_cfg_path])
            if not success:
                logger.error(f"[DEFAULT] '{grub_cfg_path}' izinleri güncellenirken hata: {output}")
                return
            logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri başarıyla varsayılana döndürüldü.")
        else:
            logger.info(f"[DEFAULT] '{grub_cfg_path}' izinleri zaten varsayılan durumda ({current_perms}).")
            
    except Exception as e:
        logger.error(f"[DEFAULT] GRUB izinleri geri alınırken hata: {e}")

#------------------------------------------------------------------------------

### 4. GÜVENSİZ PAKETLERİ YENİDEN YÜKLEME (YENİ FONKSİYON) ###

# CIS politikaları ile kaldırılmasını sağladığın paketlerin bir listesini buraya yaz.
# Geri alma işlemi bu listedeki paketleri yeniden kurmayı deneyecek.
PACKAGES_TO_REINSTALL = [
    "telnet",
    "nis",
    "rsh-client",
    "talk"
]

def revert_package_removals():
    """
    CIS politikası tarafından kaldırılmış olabilecek güvensiz paketleri
    sisteme yeniden yükler.
    """
    logger.info("[DEFAULT] Kaldırılmış paketler kontrol ediliyor...")
    
    try:
        # Paket listesini güncellemek her zaman iyi bir pratiktir.
        logger.info("[DEFAULT] Paket listesi güncelleniyor (apt-get update)...")
        success, output = run_command(['sudo', 'apt-get', 'update'])
        if not success:
            logger.warning(f"[DEFAULT] apt-get update başarısız oldu: {output}. Yine de devam ediliyor.")
    except Exception as e:
        logger.warning(f"[DEFAULT] apt-get update başarısız oldu, yine de devam ediliyor: {e}")

    for package_name in PACKAGES_TO_REINSTALL:
        try:
            # Paketin kurulu olup olmadığını kontrol et
            success, output = run_command(['dpkg', '-l', package_name])
            if not success or f"ii  {package_name}" not in output:
                logger.info(f"[DEFAULT] '{package_name}' paketi kurulu değil, varsayılana döndürmek için YÜKLENİYOR...")
                
                # Paketi yeniden yükle
                success, output = run_command(
                    ['sudo', 'apt-get', 'install', '-y', package_name]
                )
                if not success:
                    logger.error(f"[DEFAULT] '{package_name}' paketi yüklenirken hata: {output}")
                    return
                logger.info(f"[DEFAULT] '{package_name}' paketi başarıyla yüklendi.")
            else:
                # Paket zaten kuruluysa, bir şey yapmaya gerek yok.
                logger.info(f"[DEFAULT] '{package_name}' paketi zaten kurulu (varsayılan durum).")
        except Exception as e:
            logger.error(f"[DEFAULT] '{package_name}' paketi işlenirken genel hata: {e}")
#------------------------------------------------------------------------------

### 5. DEVRE DIŞI BIRAKILAN ÇEKİRDEK MODÜLLERİNİ GERİ ALMA (YENİ FONKSİYON) ###

# CIS politikaları ile devre dışı bıraktığın tüm modüllerin bir listesini buraya yaz.
# Geri alma işlemi, bu modüller için oluşturulmuş blacklist dosyalarını silecektir.
MODULES_TO_RE_ENABLE = [
    "cramfs",
    "freevxfs",
    "hfs",
    "hfsplus",
    "jffs2",
    "squashfs",
    "udf",
    "usb-storage",
    # Ağ ile ilgili olanlar (önceki loglarda gördüklerimiz)
    "dccp",
    "sctp",
    "rds",
    "tipc"
]

def revert_disabled_modules():
    """
    CIS politikası tarafından /etc/modprobe.d/ içinde oluşturulmuş olan
    modül engelleme dosyalarını kaldırır.
    """
    logger.info("[DEFAULT] Devre dışı bırakılmış çekirdek modülleri kontrol ediliyor...")
    
    for module_name in MODULES_TO_RE_ENABLE:
        # CIS politikasının oluşturduğu dosyanın tam yolu
        rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
        
        try:
            # Eğer bu dosya varsa, CIS politikası uygulanmış demektir.
            if os.path.exists(rule_path):
                logger.info(f"[DEFAULT] '{module_name}' modülü için engelleme kuralı kaldırılıyor...")
                
                # Dosyayı silerek modülün tekrar yüklenebilmesini sağla
                success, output = run_command(['sudo', 'rm', '-f', rule_path])
                if not success:
                    logger.error(f"[DEFAULT] '{module_name}' modül kuralı kaldırılırken hata: {output}")
                    continue
            else:
                # Dosya yoksa, sistem zaten varsayılan durumdadır.
                logger.info(f"[DEFAULT] '{module_name}' modülü zaten etkin (varsayılan durum).")

        except Exception as e:
            logger.error(f"[DEFAULT] '{module_name}' modülü geri alınırken hata: {e}")

#------------------------------------------------------------------------------
### 6. FSTAB DEĞİŞİKLİKLERİNİ GERİ ALMA (YENİ FONKSİYON) ###

# CIS politikaları ile /etc/fstab'a eklenen/değiştirilen mount seçenekleri
# Bu liste, `enforce_mount_option` politikasının hedeflerini içermelidir.
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
#------------------------------------------------------------------------------

# ==============================================================================
# == GERİ ALMA (REVERT) FONKSİYONLARI ===========================================
# ==============================================================================

### 6. ARAYÜZ VE PROTOKOL DEĞİŞİKLİKLERİNİ GERİ ALMA (YENİ) ###

def revert_interface_protocols():
    """
    Kablosuz ve Bluetooth için yapılan değişiklikleri geri alır.
    """
    logger.info("[DEFAULT] Arayüz ve protokol ayarları kontrol ediliyor...")
    
    # Kablosuz için oluşturulan blacklist dosyasını sil
    wifi_blacklist_file = "/etc/modprobe.d/pmys-wifi-blacklist.conf"
    if os.path.exists(wifi_blacklist_file):
        try:
            logger.info(f"[DEFAULT] Kablosuz arayüz engelleme kuralı '{wifi_blacklist_file}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', wifi_blacklist_file])
            if not success:
                logger.error(f"[DEFAULT] Kablosuz arayüz engelleme kuralı kaldırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Kablosuz arayüz engelleme kuralı başarıyla kaldırıldı.")
        except Exception as e:
            logger.error(f"[DEFAULT] Kablosuz arayüz kuralı geri alınırken hata: {e}")

    # Bluetooth servisini 'unmask' etmeyi dene
    # CIS politikası paketi kaldırmış veya servisi maskelemiş olabilir.
    # Geri alma işlemi servisi sadece 'unmask' eder, paketi yeniden kurmaz.
    try:
        success, output = run_command(['systemctl', 'is-enabled', 'bluetooth.service'])
        if "masked" in output:
            logger.info("[DEFAULT] Bluetooth servisi 'unmask' ediliyor...")
            success, output = run_command(['sudo', 'systemctl', 'unmask', 'bluetooth.service'])
            if not success:
                logger.error(f"[DEFAULT] Bluetooth servisi 'unmask' edilirken hata: {output}")
            else:
                logger.info("[DEFAULT] Bluetooth servisi başarıyla 'unmask' edildi.")
    except Exception as e:
         logger.error(f"[DEFAULT] Bluetooth servisi geri alınırken hata: {e}")


### 7. SYSCTL PARAMETRELERİNİ GERİ ALMA (YENİ) ###

# CIS politikası ile değiştirilen tüm sysctl anahtarlarını bu listeye ekle.
SYSCTL_KEYS_TO_REVERT = [
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.tcp_syncookies",
    "net.ipv6.conf.all.accept_ra"
]

def revert_sysctl_parameters():
    """
    CIS politikası tarafından /etc/sysctl.d/ altında oluşturulmuş olan
    yapılandırma dosyalarını kaldırır ve sysctl ayarlarını yeniden yükler.
    """
    logger.info("[DEFAULT] Sysctl parametreleri kontrol ediliyor...")
    
    config_dir = "/etc/sysctl.d/"
    changes_made = False
    
    for key in SYSCTL_KEYS_TO_REVERT:
        # Politikanın oluşturduğu dosya adını bul
        config_filename = key.replace('.', '_').replace('/', '_')
        config_path = f"{config_dir}99-pmys-{config_filename}.conf"
        
        if os.path.exists(config_path):
            try:
                logger.info(f"[DEFAULT] Sysctl kural dosyası '{config_path}' kaldırılıyor...")
                success, output = run_command(['sudo', 'rm', '-f', config_path])
                if not success:
                    logger.error(f"[DEFAULT] '{config_path}' kaldırılırken hata: {output}")
                changes_made = True
            except Exception as e:
                logger.error(f"[DEFAULT] '{config_path}' kaldırılırken hata: {e}")

    # Eğer en az bir dosya silindiyse, sysctl ayarlarını yeniden yükle
    if changes_made:
        try:
            logger.info("[DEFAULT] Sysctl ayarları yeniden yükleniyor...")
            # '-p' parametresi olmadan çalıştırmak, varsayılan dosyalardan ayarları yeniden okur.
            success, output = run_command(['sudo', 'sysctl', '--system'])
            if not success:
                logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Sysctl ayarları başarıyla varsayılana döndürüldü.")
        except Exception as e:
            logger.error(f"[DEFAULT] 'sysctl --system' komutu çalıştırılırken hata: {e}")

#------------------------------------------------------------------------------

### 7. APT VE GÜNCELLEME AYARLARINI GERİ ALMA (YENİ FONKSİYON) ###

def revert_apt_and_update_settings():
    """
    APT depo listesi ve otomatik güncelleme betiği değişikliklerini geri alır.
    """
    logger.info("[DEFAULT] APT ve güncelleme ayarları kontrol ediliyor...")
    
    # 1. Otomatik güncelleme için oluşturulan cron betiğini sil
    cron_script_path = "/etc/cron.daily/pmys-automatic-updates"
    if os.path.exists(cron_script_path):
        try:
            logger.info(f"[DEFAULT] Otomatik güncelleme betiği '{cron_script_path}' kaldırılıyor...")
            success, output = run_command(['sudo', 'rm', '-f', cron_script_path])
            if not success:
                logger.error(f"[DEFAULT] Otomatik güncelleme betiği kaldırılırken hata: {output}")
            else:
                logger.info("[DEFAULT] Otomatik güncelleme betiği başarıyla kaldırıldı.")
        except Exception as e:
            logger.error(f"[DEFAULT] Otomatik güncelleme betiği kaldırılırken hata: {e}")
    else:
        logger.info("[DEFAULT] Otomatik güncelleme betiği zaten mevcut değil (varsayılan durum).")

    # 2. Değiştirilen sources.list dosyasını, oluşturulan yedekten geri yükle
    sources_path = "/etc/apt/sources.list"
    # Yedek dosyalarını bulmak için /etc/apt dizinini tara
    backup_dir = "/etc/apt/"
    backup_files = [f for f in os.listdir(backup_dir) if f.startswith("sources.list.bak_")]
    
    if backup_files:
        # En son oluşturulan yedeği bul
        latest_backup = max(backup_files, key=lambda f: os.path.getmtime(os.path.join(backup_dir, f)))
        latest_backup_path = os.path.join(backup_dir, latest_backup)
        
        try:
            logger.info(f"[DEFAULT] '{sources_path}' en son yedekten ('{latest_backup}') geri yükleniyor...")
            success, output = run_command(['sudo', 'mv', latest_backup_path, sources_path])
            if not success:
                logger.error(f"[DEFAULT] '{sources_path}' geri yüklenirken hata: {output}")
            else:
                logger.info(f"[DEFAULT] '{sources_path}' başarıyla yedeğinden geri yüklendi. Paket listesi güncelleniyor...")
                run_command(['sudo', 'apt-get', 'update'])
                logger.info("[DEFAULT] Paket listesi başarıyla güncellendi.")
        except Exception as e:
            logger.error(f"[DEFAULT] '{sources_path}' geri yüklenirken hata: {e}")
    else:
        logger.info(f"[DEFAULT] '{sources_path}' için bir yedek dosyası bulunamadı, geri alma işlemi atlanıyor.")

#"------------------------------------------------------------------------------

### 8. ÇEKİRDEK GÜVENLİĞİ (PROCESS HARDENING) AYARLARINI GERİ ALMA (YENİ FONKSİYON) ###

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

#------------------------------------------------------------------------------

### 9. DOSYA İZİN VE SAHİPLİK AYARLARINI GERİ ALMA (YENİ FONKSİYON) ###

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

    # 2. 'secure_world_writable_files_and_dirs' politikasının etkilerini geri al
    # BU İŞLEM RİSKLİ OLABİLİR VE GENELLİKLE TAVSİYE EDİLMEZ.
    # Herkese yazma izni olan bir dizine eklenen 'sticky bit'i kaldırmak,
    # güvenlik açığı yaratabilir. Bu nedenle bu fonksiyon bilinçli olarak boş bırakılmıştır
    # veya sadece loglama yapar. Eğer gerçekten geri almak istiyorsan, ilgili
    # dizinleri bulup 'sudo chmod o-t /dizin/yolu' komutunu çalıştırman gerekir.
    logger.info("[DEFAULT] 'World-writable' dosyalar için geri alma işlemi atlanıyor (güvenlik nedeniyle).")
    
    # 3. 'audit_and_fix_unowned_files' politikasını geri alma
    # Bu politika bir güvenlik açığını kapattığı için geri alınması mantıklı değildir.
    # Sahipsiz bir dosyayı tekrar sahipsiz bırakmak istemeyiz.
    logger.info("[DEFAULT] 'Unowned files' için geri alma işlemi atlanıyor (güvenlik nedeniyle).")


#------------------------------------------------------------------------------
### 10. DOSYA İZİN VE SAHİPLİK AYARLARINI GERİ ALMA (YENİ FONKSİYON) ###

# 'enforce_file_permissions' politikasının hedeflediği dosyaların
# varsayılan (genellikle daha az kısıtlayıcı) izinlerini burada tanımlayabiliriz.
# Pardus/Debian sistemleri için standart varsayılanlar bunlardır.
DEFAULT_FILE_PERMISSIONS = {
    "/etc/passwd": "644",
    "/etc/shadow": "640", # Bu zaten CIS standardıyla aynı, dokunulmayacak.
    "/etc/group": "644",
    "/etc/gshadow": "640"  # Bu da CIS standardıyla aynı.
}
# Varsayılan sahiplik genellikle root:root'tur, bu yüzden sadece izinleri kontrol edeceğiz.

def revert_file_permissions_and_ownership():
    """
    Dosya izinleri ve sahipliği ile ilgili yapılan değişiklikleri geri alır.
    Güvenlik açığı oluşturabilecek veya mantıksız olan geri alma işlemleri bilinçli olarak atlanmıştır.
    """
    logger.info("[DEFAULT] Dosya izin ve sahiplik ayarları kontrol ediliyor...")

    # 1. 'enforce_file_permissions' politikasının değiştirdiği izinleri geri al
    for file_path, default_perm in DEFAULT_FILE_PERMISSIONS.items():
        if os.path.exists(file_path):
            try:
                # Mevcut izinleri al (örn: '600')
                current_perms = oct(stat.S_IMODE(os.stat(file_path).st_mode))[-3:]
                
                # Eğer mevcut izin, bizim bildiğimiz varsayılan izinden farklıysa düzelt
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

    # 2. 'secure_world_writable_files_and_dirs' politikasının etkilerini geri al
    # AÇIKLAMA: Bu politika temel bir güvenlik açığını kapatır. Bu işlemi geri almak,
    # yani bir dosyaya tekrar herkese yazma izni vermek veya bir dizinden "sticky bit"i kaldırmak,
    # sistemi doğrudan daha güvensiz bir hale getirir. Bu nedenle bu fonksiyon bilinçli olarak
    # herhangi bir eylemde bulunmaz. Bir sistemin "varsayılan" hali güvensiz olmamalıdır.
    logger.info("[DEFAULT] 'World-writable' dosyalar için geri alma işlemi atlanıyor (güvenlik nedeniyle).")
    
    # 3. 'audit_and_fix_unowned_files' politikasını geri alma
    # AÇIKLAMA: Bu politika da bir güvenlik açığını (sahipsiz dosyaları) kapatır.
    # Bu politikayı geri almak, yani bir dosyayı tekrar "sahipsiz" bırakmak anlamsız ve tehlikelidir.
    # Bu nedenle bu işlem de bilinçli olarak atlanmıştır.
    logger.info("[DEFAULT] 'Unowned files' (sahipsiz dosyalar) için geri alma işlemi atlanıyor (güvenlik nedeniyle).")
