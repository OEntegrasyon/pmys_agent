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
    ASLR'nin (kernel.randomize_va_space = 2) hem ÇALIŞAN hem de 
    KALICI yapılandırmada etkin olup olmadığını denetler.
    """
    key = "kernel.randomize_va_space"
    expected_value = "2"
    
    # Kendi 'apply' fonksiyonumuzun kullandığı kalıcı dosyanın yolu
    config_path = "/etc/sysctl.d/99-aslr-hardening.conf"
    
    running_is_correct = False
    durable_is_correct = False

    try:
        success, output = run_command(['sysctl', key])
        if success:
            current_value = output.strip().split('=')[-1].strip()
            if current_value == expected_value:
                running_is_correct = True

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                content = f.read()
                if f"{key} = {expected_value}" in content:
                    durable_is_correct = True

        if running_is_correct and durable_is_correct:
            return True, f"{key} değeri hem çalışan hem de kalıcı yapılandırmada '{expected_value}' olarak doğru ayarlanmış."
        else:
            if not running_is_correct:
                print(f"Denetim: {key} çalışan değeri yanlış (Mevcut: {current_value}). Düzeltme uygulanacak.")
            if not durable_is_correct:
                print(f"Denetim: {config_path} dosyası eksik veya içeriği yanlış. Düzeltme uygulanacak.")
                
            return apply_aslr_enabled(parameters) 

    except Exception as e:
        return False, f"ASLR kontrolünde hata: {e}"

def apply_aslr_enabled(parameters):
    """
    ASLR (kernel.randomize_va_space) değerini '2' olarak ayarlar ve kalıcı hale getirir.
    """
    key = "kernel.randomize_va_space"
    value = "2"
    config_path = "/etc/sysctl.d/99-aslr-hardening.conf"
    temp_path = "/tmp/99-aslr-hardening.conf"
    
    try:
        # 1. Kalıcı dosyayı oluştur/düzelt
        with open(temp_path, "w") as f:
            f.write(f"# GPOS tarafından CIS 1.5.1 politikası için ayarlandı\n")
            f.write(f"{key} = {value}\n")

        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}."

        # 2. Çalışan yapılandırmayı bu dosyadan yükle
        success, output = run_command(['sudo', 'sysctl', '-p', config_path])
        if not success:
            return False, f"Sysctl yapılandırması yüklenirken hata: {output}."

        return True, f"{key} değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"ASLR uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."


# ------------------------------------------------------------------------------

# Politika 2: ptrace Kapsamını Kısıtla
def restrict_ptrace_scope(username, parameters):
    """
    ptrace kapsamının (kernel.yama.ptrace_scope) hem ÇALIŞAN hem de 
    KALICI yapılandırmada '1' (Kısıtlı) olarak ayarlandığını denetler.
    """
    key = "kernel.yama.ptrace_scope"
    expected_value = "1"
    
    config_path = "/etc/sysctl.d/99-ptrace-hardening.conf"
    
    running_is_correct = False
    durable_is_correct = False

    try:
        success, output = run_command(['sysctl', key])
        if success:
            current_value = output.strip().split('=')[-1].strip()
            if current_value == expected_value:
                running_is_correct = True
            else:
                print(f"Denetim: {key} çalışan değeri yanlış (Beklenen: {expected_value}, Mevcut: {current_value}).")

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                content = f.read()
                if f"{key} = {expected_value}" in content:
                    durable_is_correct = True

        if running_is_correct and durable_is_correct:
            return True, f"{key} değeri hem çalışan hem de kalıcı yapılandırmada '{expected_value}' olarak doğru ayarlanmış."
        else:
            if not durable_is_correct:
                print(f"Denetim: {config_path} dosyası eksik veya içeriği yanlış. Düzeltme uygulanacak.")
                
            # 'apply' fonksiyonunu 'parameters' ile çağır
            return apply_ptrace_scope(parameters)

    except Exception as e:
        return False, f"ptrace kontrolünde hata: {e}"

def apply_ptrace_scope(parameters):
    """
    ptrace kapsamını (kernel.yama.ptrace_scope) '1' olarak ayarlar ve kalıcı hale getirir.
    """
    key = "kernel.yama.ptrace_scope"
    value = "1"
    config_path = "/etc/sysctl.d/99-ptrace-hardening.conf"
    temp_path = "/tmp/99-ptrace-hardening.conf"

    try:
        with open(temp_path, "w") as f:
            f.write(f"# GPOS tarafından CIS 1.5.2 politikası için ayarlandı\n")
            f.write(f"{key} = {value}\n")

        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}."

        success, output = run_command(['sudo', 'sysctl', '-p', config_path])
        if not success:
            return False, f"Sysctl yapılandırması yüklenirken hata: {output}."

        return True, f"{key} değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"ptrace uygulanırken hata: {e}."

# ------------------------------------------------------------------------------

# Politika 3: Çekirdek Dökümlerini (Core Dumps) Kısıtla
def restrict_core_dumps(username, parameters):
    """
    CIS 1.5.3: Core dump kısıtlamalarını denetler.
    1. 'fs.suid_dumpable = 0' ayarını (hem çalışan hem kalıcı) denetler.
    2. '* hard core 0' ayarını (kalıcı) denetler.
    
    Not: Bu kod, 'systemd-coredump' servisinin kurulu OLMADIĞINI varsayar.
    """
    
    sysctl_key = "fs.suid_dumpable"
    sysctl_value = "0"
    sysctl_config_path = "/etc/sysctl.d/99-coredump-hardening.conf" 
    
    sysctl_running_ok = False
    sysctl_durable_ok = False

    try:
        success, output = run_command(['sysctl', sysctl_key])
        if success and output.strip().split('=')[-1].strip() == sysctl_value:
            sysctl_running_ok = True

        if os.path.exists(sysctl_config_path):
            with open(sysctl_config_path, "r") as f:
                content = f.read()
                if f"{sysctl_key} = {sysctl_value}" in content:
                    sysctl_durable_ok = True

    except Exception as e:
        print(f"Uyarı: sysctl denetiminde hata: {e}")

    limits_line = "* hard core 0"
    limits_config_path = "/etc/security/limits.d/99-coredump-hardening.conf" 
    
    limits_durable_ok = False
    
    try:
        if os.path.exists(limits_config_path):
            with open(limits_config_path, "r") as f:
                content = f.read()
                if re.search(r"^\s*\*\s+hard\s+core\s+0", content, re.MULTILINE):
                    limits_durable_ok = True
                    
    except Exception as e:
        print(f"Uyarı: limits denetiminde hata: {e}")

    if sysctl_running_ok and sysctl_durable_ok and limits_durable_ok:
        return True, "Core dump kısıtlamaları (sysctl ve limits.d) zaten doğru ayarlanmış."
    else:
        if not sysctl_running_ok: print(f"Denetim: {sysctl_key} çalışan değeri yanlış.")
        if not sysctl_durable_ok: print(f"Denetim: {sysctl_config_path} eksik veya hatalı.")
        if not limits_durable_ok: print(f"Denetim: {limits_config_path} eksik veya hatalı.")
        
        return apply_core_dumps(parameters)

def apply_core_dumps(parameters):
    """
    Core dump kısıtlamalarını (sysctl ve limits.d) kalıcı ve 
    idempotent (tekrarlanabilir) bir şekilde uygular.
    """
    
    try:
        key = "fs.suid_dumpable"
        value = "0"
        config_path = "/etc/sysctl.d/99-coredump-hardening.conf"
        temp_path = "/tmp/99-coredump-hardening.conf"
        
        with open(temp_path, "w") as f:
            f.write(f"# GPOS tarafından CIS 1.5.3 politikası için ayarlandı\n")
            f.write(f"{key} = {value}\n")
            
        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"sysctl geçici dosyası taşınırken hata: {output}."

        success, output = run_command(['sudo', 'sysctl', '-p', config_path])
        if not success:
            return False, f"Sysctl yapılandırması yüklenirken hata: {output}."

    except Exception as e:
        return False, f"Core dump için sysctl uygulanırken hata: {e}."

    try:
        limits_config_path = "/etc/security/limits.d/99-coredump-hardening.conf"
        temp_path = "/tmp/99-coredump-hardening.conf.limits"
        limits_line = "* hard core 0"
        
        with open(temp_path, "w") as f:
            f.write(f"# GPOS tarafından CIS 1.5.3 politikası için ayarlandı\n")
            f.write(f"{limits_line}\n")
            
        success, output = run_command(['sudo', 'mv', temp_path, limits_config_path])
        if not success:
            return False, f"limits.d geçici dosyası taşınırken hata: {output}."

    except Exception as e:
        return False, f"limits.d düzenlenirken hata: {e}."

    return True, "Core dump kısıtlamaları (sysctl ve limits.d) başarıyla uygulandı. (Limits ayarı bir sonraki girişte (login) geçerli olacaktır)"