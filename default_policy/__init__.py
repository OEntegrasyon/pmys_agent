from logger import logger

# Adım 1: Diğer dosyalardaki ana geri alma fonksiyonlarını import et.
# Her dosyanın içinde, o kategoriyle ilgili tüm işlemleri yapan bir ana fonksiyon olmalı.
# Fonksiyon isimlerinin tutarlı olması, kodu daha okunabilir kılar.
from .revert_apparmor_settings import revert_apparmor_settings
from .revert_login_banners import revert_login_banners
from .revert_bootloader_settings import revert_bootloader_settings
from .revert_filesystem_kernels import revert_disabled_modules
from .revert_file_permissions_and_ownership import revert_file_permissions_and_ownership
from .revert_interface_protocols import revert_interface_protocols
from .revert_package_removals import revert_services_settings
from .revert_process_hardening import revert_process_hardening
from .revert_firewall import revert_firewall_settings
from .revert_sudo import revert_sudo_settings
from .revert_network_kernel_modules import revert_disabled_network_modules
from .revert_network_kernel_parameters import revert_sysctl_parameters



from .revert_time_synchronization import (
    revert_timesyncd_service,
    revert_systemd_timesyncd_authorized_timeserver,
    revert_timesyncd_service_enabled,
    revert_chrony_authorized_timeserver,
    revert_chrony_running_as_chrony,
    revert_timesync_service
)

from .revert_job_schedulers import (
    revert_cron_service_policy,
    revert_crontab_file_authorities,
    revert_cron_hourly_permissions,
    revert_cron_daily_authorities,
    revert_cron_weekly_permissions,
    revert_cron_monthly_permissions,
    revert_cron_d_permissions,
    revert_crontab_restriction
)

from .revert_ssh_configure import (
    revert_sshd_config_permissions,
    revert_ssh_private_host_key_permissions,
    revert_ssh_public_host_key_permissions,
    revert_sshd_access,
    revert_sshd_banner,
    revert_sshd_ciphers,
    revert_ssh_client_alive,
    revert_sshd_disableforwarding,
    revert_sshd_gssapiauthentication,
    revert_sshd_hostbasedauthentication,
    revert_sshd_ignorerhosts,
    revert_sshd_kexalgorithms,
    revert_sshd_logingracetime,
    revert_sshd_loglevel,
    revert_sshd_macs,
    revert_sshd_maxauthtries,
    revert_sshd_maxsessions,
    revert_sshd_maxstartups,
    revert_sshd_permitemptypasswords,
    revert_sshd_permitrootlogin,
    revert_sshd_permit_user_environment,
    revert_sshd_usepam
)

from .revert_pam import (
    revert_libpam_runtime,
    revert_libpam_modules,
    revert_libpam_pwquality,
    revert_pam_unix_enabled,
    revert_pam_faillock,
    revert_pam_pwquality,
    revert_pwhistory,
    revert_failed_attempts_lockout,
    revert_unlock_time,
    revert_root_account_lock,
    revert_pwquality_difok,
    revert_min_password_length,
    revert_pw_complexity,
    revert_maxrepeat,
    revert_maxsequence,
    revert_dictcheck,
    revert_enforcing,
    revert_enforce_for_root,
    revert_password_history_remember,
    revert_password_history_enforce_for_root,
    revert_password_history_use_authtok,
    revert_pam_unix_nullok,
    revert_pam_unix_remember,
    revert_pam_unix_strong_hash,
    revert_pam_unix_use_authtok
)

from .revert_user_account import (
    revert_password_expiration,
    revert_min_password_days,
    revert_password_warn_days,
    revert_password_hashing_algorithm,
    revert_inactive_password_lock,
    revert_last_password_change_in_past,
    revert_only_root_uid0,
    revert_only_root_gid0,
    revert_only_root_group_gid0,
    revert_root_account_access,
    revert_root_path_integrity,
    revert_root_umask,
    revert_system_accounts_shell,
    revert_accounts_without_login_shell_locked,
    revert_ensure_nologin_not_in_shells,
    revert_ensure_shell_timeout,
    revert_umask
)

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
    _revert_safely(revert_login_banners, "Login Banners")
    _revert_safely(revert_bootloader_settings, "Bootloader Settings")
    _revert_safely(revert_disabled_modules, "Kernel Module Disabling")
    _revert_safely(revert_file_permissions_and_ownership, "File Permissions & Ownership")
    _revert_safely(revert_interface_protocols, "Interface/Protocol Disabling")
    _revert_safely(revert_services_settings, "Service Settings")
    _revert_safely(revert_process_hardening, "Process Hardening")
    _revert_safely(revert_sysctl_parameters, "Sysctl Parameters")
    _revert_safely(revert_firewall_settings, "Firewall Settings")
    _revert_safely(revert_sudo_settings, "Sudo Settings")
    _revert_safely(revert_disabled_network_modules, "Network Kernel Module Disabling")
    _revert_safely(revert_sysctl_parameters, "Network Sysctl Parameters")



    
    _revert_safely(revert_timesyncd_service, "timesyncd Service")
    _revert_safely(revert_systemd_timesyncd_authorized_timeserver, "systemd-timesyncd Authorized Timeserver")
    _revert_safely(revert_timesyncd_service_enabled, "timesyncd Service Enabled")
    _revert_safely(revert_chrony_authorized_timeserver, "chrony Authorized Timeserver")
    _revert_safely(revert_chrony_running_as_chrony, "chrony Running as _chrony User")
    _revert_safely(revert_timesync_service, "Time Synchronization Service")
    _revert_safely(revert_cron_service_policy, "Cron Service")
    _revert_safely(revert_crontab_file_authorities, "Crontab File Authorities")
    _revert_safely(revert_cron_hourly_permissions, "Cron Hourly Permissions")
    _revert_safely(revert_cron_daily_authorities, "Cron Daily Authorities")
    _revert_safely(revert_cron_weekly_permissions, "Cron Weekly Permissions")
    _revert_safely(revert_cron_monthly_permissions, "Cron Monthly Permissions")
    _revert_safely(revert_cron_d_permissions, "Cron.d Permissions")
    _revert_safely(revert_crontab_restriction, "Crontab Restriction")
    _revert_safely(revert_sshd_config_permissions, "SSHD Config Permissions")
    _revert_safely(revert_ssh_private_host_key_permissions, "SSH Private Host Key Permissions")
    _revert_safely(revert_ssh_public_host_key_permissions, "SSH Public Host Key Permissions")
    _revert_safely(revert_sshd_access, "SSHD Access Restrictions")
    _revert_safely(revert_sshd_banner, "SSHD Banner")
    _revert_safely(revert_sshd_ciphers, "SSHD Ciphers")
    _revert_safely(revert_ssh_client_alive, "SSH ClientAlive Settings")
    _revert_safely(revert_sshd_disableforwarding, "SSHD Disable Forwarding")
    _revert_safely(revert_sshd_gssapiauthentication, "SSHD GSSAPIAuthentication")
    _revert_safely(revert_sshd_hostbasedauthentication, "SSHD HostbasedAuthentication")
    _revert_safely(revert_sshd_ignorerhosts, "SSHD IgnoreRhosts")
    _revert_safely(revert_sshd_kexalgorithms, "SSHD KexAlgorithms")
    _revert_safely(revert_sshd_logingracetime, "SSHD LoginGraceTime")
    _revert_safely(revert_sshd_loglevel, "SSHD LogLevel")
    _revert_safely(revert_sshd_macs, "SSHD MACs Algorithms")
    _revert_safely(revert_sshd_maxauthtries, "SSHD MaxAuthTries")
    _revert_safely(revert_sshd_maxsessions, "SSHD MaxSessions")
    _revert_safely(revert_sshd_maxstartups, "SSHD MaxStartups")
    _revert_safely(revert_sshd_permitemptypasswords, "SSHD PermitEmptyPasswords")
    _revert_safely(revert_sshd_permitrootlogin, "SSHD PermitRootLogin")
    _revert_safely(revert_sshd_permit_user_environment, "SSHD PermitUserEnvironment")
    _revert_safely(revert_sshd_usepam, "SSHD UsePAM")
    _revert_safely(revert_libpam_runtime, "libpam-runtime Configuration")
    _revert_safely(revert_libpam_modules, "libpam Modules Configuration")
    _revert_safely(revert_libpam_pwquality, "PAM Password Quality")
    _revert_safely(revert_pam_unix_enabled, "PAM Unix Module")
    _revert_safely(revert_pam_faillock, "PAM Faillock Module")
    _revert_safely(revert_pam_pwquality, "PAM Pwquality Module")
    _revert_safely(revert_pwhistory, "Password History")
    _revert_safely(revert_failed_attempts_lockout, "Failed Attempts Lockout")
    _revert_safely(revert_unlock_time, "Unlock Time")
    _revert_safely(revert_root_account_lock, "Root Account Lock")
    _revert_safely(revert_pwquality_difok, "Password Quality difok")
    _revert_safely(revert_min_password_length, "Minimum Password Length")
    _revert_safely(revert_pw_complexity, "Password Complexity")
    _revert_safely(revert_maxrepeat, "Maxrepeat in Passwords")
    _revert_safely(revert_maxsequence, "Maxsequence in Passwords")
    _revert_safely(revert_dictcheck, "Dictionary Check in Passwords")
    _revert_safely(revert_enforcing, "Revert enforcing")
    _revert_safely(revert_enforce_for_root, "Revert enforce_for_root")
    _revert_safely(revert_password_history_remember, "Password History Remember")
    _revert_safely(revert_password_history_enforce_for_root, "Password History Enforce for Root")
    _revert_safely(revert_password_history_use_authtok, "Password History Use Authtok")
    _revert_safely(revert_pam_unix_nullok, "PAM Unix nullok")
    _revert_safely(revert_pam_unix_remember, "PAM Unix remember")
    _revert_safely(revert_pam_unix_strong_hash, "PAM Unix strong hash")
    _revert_safely(revert_pam_unix_use_authtok, "PAM Unix use_authtok")
    _revert_safely(revert_password_expiration, "Password Expiration")
    _revert_safely(revert_min_password_days, "Minimum Password Days")
    _revert_safely(revert_password_warn_days, "Password Warning Days")
    _revert_safely(revert_password_hashing_algorithm, "Password Hashing Algorithm")
    _revert_safely(revert_inactive_password_lock, "Inactive Password Lock")
    _revert_safely(revert_last_password_change_in_past, "Last Password Change in Past")
    _revert_safely(revert_only_root_uid0, "Only root UID 0")
    _revert_safely(revert_only_root_gid0, "Only root GID 0")
    _revert_safely(revert_only_root_group_gid0, "Only root group GID 0")
    _revert_safely(revert_root_account_access, "Root Account Access")
    _revert_safely(revert_root_path_integrity, "Root Path Integrity")
    _revert_safely(revert_root_umask, "Root Umask")
    _revert_safely(revert_system_accounts_shell, "System Accounts Shell")
    _revert_safely(revert_accounts_without_login_shell_locked, "Accounts Without Login Shell Locked")
    _revert_safely(revert_ensure_nologin_not_in_shells, "Ensure /sbin/nologin Not in Shells")
    _revert_safely(revert_ensure_shell_timeout, "Ensure Shell Timeout")
    _revert_safely(revert_umask, "Umask for Users")

    logger.info("="*50)
    logger.info("Varsayılan ayarlara döndürme işlemi tamamlandı.")
    logger.info("="*50)

def _revert_safely(revert_function, policy_name):
    """Hata olsa bile diğerlerinin çalışmasını sağlayan yardımcı fonksiyon."""
    try:
        revert_function()
    except Exception as e:
        logger.error(f"'{policy_name}' ayarları geri alınırken hata oluştu: {e}")