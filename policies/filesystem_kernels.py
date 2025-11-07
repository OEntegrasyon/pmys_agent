import os
import re
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
    
    Bu fonksiyon, CIS'in denetim mantığına uyacak şekilde güncellenmiştir.
    """
    module_name = parameters.get("module_name")
    if not module_name:
        return False, "Politika hatası: 'module_name' parametresi belirtilmemiş."
    mod_name_for_rules = module_name.replace('-', '_')

    try:

        lsmod_process = subprocess.run(['lsmod'], capture_output=True, text=True, check=True)
        is_loaded = False
        for line in lsmod_process.stdout.splitlines():
            if line.startswith(mod_name_for_rules + ' '):
                is_loaded = True
                break
            
        modprobe_process = subprocess.run(['modprobe', '--showconfig'], capture_output=True, text=True, check=True)
        config_output = modprobe_process.stdout

        install_rule_found = re.search(
            r"^\s*install\s+" + re.escape(mod_name_for_rules) + r"\s+(/bin/true|/bin/false)\s*$",
            config_output,
            re.MULTILINE
        )
        
        # Kural 2: 'blacklist modul_adi'
        blacklist_rule_found = re.search(
            r"^\s*blacklist\s+" + re.escape(mod_name_for_rules) + r"\s*$",
            config_output,
            re.MULTILINE
        )

        rules_correct = bool(install_rule_found and blacklist_rule_found)

        if not is_loaded and rules_correct:
            return True, f"{module_name} modülü zaten devre dışı bırakılmış (Uyumlu)."
        else:
            if is_loaded:
                print(f"Denetim Başarısız: '{module_name}' (veya {mod_name_for_rules}) modülü o an yüklü.")
            if not rules_correct:
                print(f"Denetim Başarısız: '{module_name}' için 'modprobe --showconfig' çıktısında 'install' veya 'blacklist' kuralları eksik/yanlış.")
                if not install_rule_found:
                    print(f"Eksik kural: install {mod_name_for_rules} /bin/false (veya /bin/true)")
                if not blacklist_rule_found:
                     print(f"Eksik kural: blacklist {mod_name_for_rules}")

            return apply_module_disabled(module_name, mod_name_for_rules)

    except subprocess.CalledProcessError as e:
        return False, f"Komut çalıştırılamadı ('lsmod' veya 'modprobe'): {e}"
    except Exception as e:
        return False, f"Modül '{module_name}' denetiminde hata: {e}"

def apply_module_disabled(original_module_name: str, module_name_for_rules: str) -> tuple[bool, str]:
    """
    CIS standardına uygun olarak modülü devre dışı bırakır.
    'usb-storage' gibi durumlar için doğru modül adını ('usb_storage') kullanır.
    """
 
    rule_path = f"/etc/modprobe.d/{original_module_name}-cis-blacklist.conf"
    temp_path = f"/tmp/{original_module_name}-blacklist.conf.tmp"
    
    rule_content = (
        f"# CIS 1.1.1.x uyarınca yönetilmektedir.\n"
        f"# {original_module_name} modülünü devre dışı bırakır.\n"
        f"install {module_name_for_rules} /bin/false\n"
        f"blacklist {module_name_for_rules}\n"
    )

    try:
        with open(temp_path, "w") as f:
            f.write(rule_content)

        success, output = run_command(['sudo', 'mv', temp_path, rule_path])
        if not success:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False, f"Modül kural dosyası ({rule_path}) oluşturulamadı: {output}"
        
        run_command(['sudo', 'chown', 'root:root', rule_path])
        run_command(['sudo', 'chmod', '0644', rule_path])

        is_loaded_check = subprocess.run(['lsmod'], capture_output=True, text=True, check=True)
        is_loaded = False
        for line in is_loaded_check.stdout.splitlines():
            if line.startswith(module_name_for_rules + ' '):
                is_loaded = True
                break

        if is_loaded:
            print(f"Bilgi: '{module_name_for_rules}' modülü yüklü, sistemden kaldırılıyor...")
            success_unload, out_unload = run_command(['sudo', 'modprobe', '-r', module_name_for_rules])
            if not success_unload:

                print(f"Uyarı: '{module_name_for_rules}' modülü kaldırılamadı (muhtemelen kullanımda): {out_unload}")
                return False, f"'{module_name_for_rules}' modülü kaldırılamadı (kullanımda olabilir). Kurallar yazıldı ancak modül hala yüklü."

        return True, f"{original_module_name} modülü başarıyla devre dışı bırakıldı ve kurallar uygulandı."
    
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False, f"Modül '{original_module_name}' devre dışı bırakılırken hata: {e}"
