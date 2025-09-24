import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
import re
# ==============================================================================
# == ÇEKİRDEK (KERNEL) GÜVENLİĞİ POLİTİKALARI PROCESS HARDENING ==================================
# ==============================================================================

# Politika 1: ASLR (Address Space Layout Randomization) Etkinleştir
def enforce_aslr_enabled(username, parameters):
    """
    Bellek adresi yerleşimini rastgele hale getiren ASLR'nin etkin olup olmadığını kontrol eder.
    (kernel.randomize_va_space = 2)
    """
    # Bu politika parametre gerektirmez.
    key = "kernel.randomize_va_space"
    expected_value = "2"
    
    try:
        result = subprocess.run(['sysctl', key], capture_output=True, text=True, check=True)
        current_value = result.stdout.strip().split('=')[-1].strip()

        if current_value == expected_value:
            return True, f"{key} değeri zaten '{expected_value}' olarak doğru ayarlanmış."
        else:
            return apply_aslr_enabled()
            
    except subprocess.CalledProcessError:
        # Anahtar hiç var olmayabilir, bu durumda oluşturmayı deneriz.
        return apply_aslr_enabled()
    except Exception as e:
        return False, f"ASLR kontrolünde hata: {e}"

def apply_aslr_enabled():
    """
    ASLR (kernel.randomize_va_space) değerini '2' olarak ayarlar ve kalıcı hale getirir.
    """
    key = "kernel.randomize_va_space"
    value = "2"
    config_path = "/etc/sysctl.d/99-aslr-hardening.conf"
    temp_path = "/tmp/99-aslr-hardening.conf"
    
    try:
        with open(temp_path, "w") as f:
            f.write(f"{key} = {value}\n")
        
        subprocess.run(['sudo', 'mv', temp_path, config_path], check=True)
        subprocess.run(['sudo', 'sysctl', '-p', config_path], check=True)
        
        return True, f"{key} değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"ASLR uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."


# ------------------------------------------------------------------------------

# Politika 2: ptrace Kapsamını Kısıtla
def restrict_ptrace_scope(username, parameters):
    """
    Süreçlerin birbirini ayıklamasını (debug) kısıtlar.
    (kernel.yama.ptrace_scope = 1)
    """
    # Bu politika parametre gerektirmez.
    key = "kernel.yama.ptrace_scope"
    expected_value = "1"
    
    try:
        result = subprocess.run(['sysctl', key], capture_output=True, text=True, check=True)
        current_value = result.stdout.strip().split('=')[-1].strip()

        if current_value == expected_value:
            return True, f"{key} değeri zaten '{expected_value}' olarak doğru ayarlanmış."
        else:
            return apply_ptrace_scope()
            
    except subprocess.CalledProcessError:
        return apply_ptrace_scope()
    except Exception as e:
        return False, f"ptrace kontrolünde hata: {e}"

def apply_ptrace_scope():
    """
    ptrace kapsamını (kernel.yama.ptrace_scope) '1' olarak ayarlar ve kalıcı hale getirir.
    """
    key = "kernel.yama.ptrace_scope"
    value = "1"
    config_path = "/etc/sysctl.d/99-ptrace-hardening.conf"
    temp_path = "/tmp/99-ptrace-hardening.conf"

    try:
        with open(temp_path, "w") as f:
            f.write(f"{key} = {value}\n")

        subprocess.run(['sudo', 'mv', temp_path, config_path], check=True)
        subprocess.run(['sudo', 'sysctl', '-p', config_path], check=True)

        return True, f"{key} değeri başarıyla '{value}' olarak ayarlandı."
    except Exception as e:
        return False, f"ptrace uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."

# ------------------------------------------------------------------------------

# Politika 3: Çekirdek Dökümlerini (Core Dumps) Kısıtla
def restrict_core_dumps(username, parameters):
    """
    SUID programlarının core dump oluşturmasını engeller ve genel limiti sıfırlar.
    """
    # Bu politika parametre gerektirmez.
    sysctl_key = "fs.suid_dumpable"
    expected_sysctl_value = "0"
    limits_path = "/etc/security/limits.conf"
    expected_limit_line = "* hard core 0"
    
    try:
        # Adım 1: sysctl değerini kontrol et
        sysctl_configured = False
        try:
            result = subprocess.run(['sysctl', sysctl_key], capture_output=True, text=True, check=True)
            current_sysctl_value = result.stdout.strip().split('=')[-1].strip()
            if current_sysctl_value == expected_sysctl_value:
                sysctl_configured = True
        except subprocess.CalledProcessError:
            sysctl_configured = False # Anahtar yoksa, ayarlı değil demektir.

        # Adım 2: limits.conf dosyasını kontrol et
        limit_configured = False
        if os.path.exists(limits_path):
            with open(limits_path, "r") as f:
                content = f.read()
                if re.search(r"^\s*\*\s+hard\s+core\s+0", content, re.MULTILINE):
                    limit_configured = True
        
        # Adım 3: Sonuçları değerlendir
        if sysctl_configured and limit_configured:
            return True, "Core dump kısıtlamaları (sysctl ve limits.conf) zaten doğru ayarlanmış."
        else:
            # Eksik bir ayar varsa, hepsini yeniden uygula
            return apply_core_dumps()
            
    except Exception as e:
        return False, f"Core dump kontrolünde hata: {e}"


def apply_core_dumps():
    """
    Core dump kısıtlamalarını (sysctl ve limits.conf) uygular.
    """
    # Adım 1: sysctl değerini uygula
    try:
        key = "fs.suid_dumpable"
        value = "0"
        config_path = "/etc/sysctl.d/99-coredump-hardening.conf"
        temp_path = "/tmp/99-coredump-hardening.conf"
        with open(temp_path, "w") as f:
            f.write(f"{key} = {value}\n")
        subprocess.run(['sudo', 'mv', temp_path, config_path], check=True)
        subprocess.run(['sudo', 'sysctl', '-p', config_path], check=True)
    except Exception as e:
        return False, f"Core dump için sysctl uygulanırken hata: {e}. sudoers'ı kontrol edin."

    # Adım 2: limits.conf değerini uygula
    try:
        limits_path = "/etc/security/limits.conf"
        expected_limit_line = "* hard core 0"
        append_content = f"\n# CIS: Core dumps disabled for security\n{expected_limit_line}\n"
        
        # Dosyaya ekleme işlemini sudo ile güvenli bir şekilde yap
        subprocess.run(
            f"sudo sh -c 'echo \"{append_content}\" >> {limits_path}'",
            shell=True, check=True
        )
        
    except Exception as e:
        return False, f"limits.conf düzenlenirken hata: {e}. sudoers'ı kontrol edin."

    return True, "Core dump kısıtlamaları (sysctl ve limits.conf) başarıyla uygulandı."
