from logger import logger

# Adım 1: Diğer dosyalardaki ana geri alma fonksiyonlarını import et.
# Her dosyanın içinde, o kategoriyle ilgili tüm işlemleri yapan bir ana fonksiyon olmalı.
# Fonksiyon isimlerinin tutarlı olması, kodu daha okunabilir kılar.
from .revert_apparmor_settings import revert_apparmor_settings
from .revert_apt_and_update_settings import revert_apt_and_update_settings
from .revert_login_banners import revert_login_banners
from .revert_bootloader_settings import revert_bootloader_settings
from .revert_disabled_modules import revert_disabled_modules
from .revert_file_permissions_and_ownership import revert_file_permissions_and_ownership
from .revert_fstab_changes import revert_fstab_changes
from .revert_interface_protocols import revert_interface_protocols
from .revert_package_removals import revert_services_settings
from .revert_process_hardening import revert_process_hardening
from .revert_sysctl_parameters import revert_sysctl_parameters
from .revert_firewall import revert_firewall_settings
from .revert_sudo import revert_sudo_settings




def restore_all_to_default():
    """
    Tüm politika modüllerindeki 'revert' fonksiyonlarını çağırarak
    sistemi varsayılan ayarlarına döndürür. Bu, paketin ana giriş noktasıdır.
    """
    logger.info("="*50)
    logger.info("Sistem varsayılan ayarlara döndürülüyor...")
    logger.info("="*50)

    # Adım 2: Import edilen tüm fonksiyonları sırayla ve güvenli bir şekilde çağır.
    _revert_safely(revert_apparmor_settings, "AppArmor")
    _revert_safely(revert_apt_and_update_settings, "APT & Update Settings")
    _revert_safely(revert_login_banners, "Login Banners")
    _revert_safely(revert_bootloader_settings, "Bootloader Settings")
    _revert_safely(revert_disabled_modules, "Kernel Module Disabling")
    _revert_safely(revert_file_permissions_and_ownership, "File Permissions & Ownership")
    _revert_safely(revert_fstab_changes, "Fstab Changes")
    _revert_safely(revert_interface_protocols, "Interface/Protocol Disabling")
    _revert_safely(revert_services_settings, "Service Settings")
    _revert_safely(revert_process_hardening, "Process Hardening")
    _revert_safely(revert_sysctl_parameters, "Sysctl Parameters")
    _revert_safely(revert_firewall_settings, "Firewall Settings")
    _revert_safely(revert_sudo_settings, "Sudo Settings")


    
    logger.info("="*50)
    logger.info("Varsayılan ayarlara döndürme işlemi tamamlandı.")
    logger.info("="*50)

def _revert_safely(revert_function, policy_name):
    """Hata olsa bile diğerlerinin çalışmasını sağlayan yardımcı fonksiyon."""
    try:
        revert_function()
    except Exception as e:
        logger.error(f"'{policy_name}' ayarları geri alınırken hata oluştu: {e}")