import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command


# ==============================================================================
# == ÇEKİRDEK MODÜLÜ DEVRE DIŞI BIRAKMA 8 Politika  =========
# ==============================================================================

# Sunucuda "Politika Tipi" olarak kaydedeceğiniz isim budur.
def check_module_disabled(username, parameters):
    """
    CIS Kuralı: Belirtilen bir çekirdek modülünün yüklenmesini engeller.
    Hangi modülün engelleneceği, 'parameters' içindeki 'module_name' anahtarıyla belirtilir.
    """
    # 1. Sunucudan gelen parametrelerin içinden 'module_name' değerini alıyoruz.
    module_name = parameters.get("module_name")

    # 2. Parametrenin gönderilip gönderilmediğini kontrol ediyoruz.
    if not module_name:
        return False, "Politika hatası: Hangi modülün devre dışı bırakılacağı 'module_name' parametresi ile belirtilmemiş."

    # 3. Kuralın varlığını ve içeriğini kontrol et.
    rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
    expected_content = f"install {module_name} /bin/true"
    
    try:
        if os.path.exists(rule_path):
            with open(rule_path, "r") as f:
                content = f.read()
            
            if expected_content in content:
                # Her şey yolunda, kural zaten mevcut ve doğru.
                return True, f"{module_name} modülü zaten devre dışı."
            else:
                # Dosya var ama içeriği yanlış, yeniden uygula.
                return apply_module_disabled(module_name)
        else:
            # Kural dosyası hiç yok, uygula.
            return apply_module_disabled(module_name)
            
    except Exception as e:
        return False, f"Modül kontrolünde hata: {e}"

def apply_module_disabled(module_name: str) -> tuple[bool, str]:
    """
    Belirtilen çekirdek modülünü /etc/modprobe.d/ içinde bir kural oluşturarak
    devre dışı bırakır. Sadece check_module_disabled tarafından çağrılır.
    """
    rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
    temp_path = f"/tmp/{module_name}-blacklist.conf"
    rule_content = f"install {module_name} /bin/true\n"

    try:
        # Kuralı önce geçici bir dosyaya yaz
        with open(temp_path, "w") as f:
            f.write(rule_content)

        # sudo ile dosyayı kalıcı yerine taşı
        subprocess.run(['sudo', 'mv', temp_path, rule_path], check=True)

        return True, f"{module_name} modülü başarıyla devre dışı bırakıldı."
    
    except PermissionError:
        return False, f"Yetki hatası: {temp_path} dosyasına yazma izni yok."
    except subprocess.CalledProcessError as e:
        return False, f"sudo veya mv komutunda hata: {e}. 'sudoers' dosyasını kontrol edin."
    except Exception as e:
        return False, f"Modül devre dışı bırakılırken genel bir hata oluştu: {e}"