import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command


# ==============================================================================
# == ÇEKİRDEK MODÜLÜ DEVRE DIŞI BIRAKMA 8 Politika  =========
# ==============================================================================

def check_module_disabled(username, parameters):
    """
    CIS Kuralı: Belirtilen bir çekirdek modülünün (örn: cramfs) 
    yüklü OLMADIĞINI ve yüklenemez olduğunu DENETLER.
    """
    module_name = parameters.get("module_name")
    if not module_name:
        return False, "Politika hatası: 'module_name' parametresi belirtilmemiş."

    rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
    
    try:
        # --- DENETİM 1: Modül o an yüklü mü? ---
        lsmod_process = subprocess.run(['lsmod'], capture_output=True, text=True, check=True)
        is_loaded = module_name in lsmod_process.stdout
        
        # --- DENETİM 2: Kalıcı kurallar doğru mu? ---
        rules_correct = False
        if os.path.exists(rule_path):
            with open(rule_path, "r") as f:
                content = f.read()
                # Her iki kuralın da (doğru olanların) dosyada olmasını bekle
                if f"install {module_name} /bin/false" in content and f"blacklist {module_name}" in content:
                    rules_correct = True

        if not is_loaded and rules_correct:
            return True, f"{module_name} modülü zaten devre dışı bırakılmış (Uyumlu)."
        else:
            if is_loaded:
                print(f"Denetim Başarısız: '{module_name}' modülü o an yüklü.")
            if not rules_correct:
                print(f"Denetim Başarısız: '{rule_path}' dosyasındaki kurallar eksik veya yanlış.")

            return apply_module_disabled(module_name)

    except subprocess.CalledProcessError as e:
        return False, f"'lsmod' komutu çalıştırılamadı: {e}"
    except Exception as e:
        return False, f"Modül '{module_name}' denetiminde hata: {e}"

def apply_module_disabled(module_name: str) -> tuple[bool, str]:
    """
    CIS standardına uygun olarak modülü devre dışı bırakır.
    1. Kalıcı kural dosyası oluşturur (/bin/false ve blacklist).
    2. Modül o an yüklüyse sistemden kaldırır.
    """
    rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
    temp_path = f"/tmp/{module_name}-blacklist.conf.tmp"
    
    rule_content = (
        f"# GPOS ajanı tarafından CIS 1.1.1.1 (ve benzeri) uyarınca yönetilmektedir.\n"
        f"install {module_name} /bin/false\n"
        f"blacklist {module_name}\n"
    )

    try:
        with open(temp_path, "w") as f:
            f.write(rule_content)

        success, output = run_command(['sudo', 'mv', temp_path, rule_path])
        if not success:
            return False, f"Modül kural dosyası ({rule_path}) oluşturulamadı: {output}"
        
        run_command(['sudo', 'chown', 'root:root', rule_path])
        run_command(['sudo', 'chmod', '0644', rule_path])

        is_loaded_check = subprocess.run(['lsmod'], capture_output=True, text=True, check=True)
        if module_name in is_loaded_check.stdout:
            print(f"Bilgi: '{module_name}' modülü yüklü, sistemden kaldırılıyor...")
            success_unload, out_unload = run_command(['sudo', 'modprobe', '-r', module_name])
            if not success_unload:
                return False, f"'{module_name}' modülü yüklüydü ancak kaldırılamadı (muhtemelen kullanımda): {out_unload}"

        return True, f"{module_name} modülü başarıyla devre dışı bırakıldı ve kurallar uygulandı."
    
    except Exception as e:
        return False, f"Modül '{module_name}' devre dışı bırakılırken hata: {e}"