import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command

# ==============================================================================
# == GÜVENSİZ PAKETLERİ KALDIRMA POLİTİKASI ===================================
# ==============================================================================

def ensure_package_is_removed(username, parameters):
    """
    Parametre olarak belirtilen bir paketin sistemde kurulu olup olmadığını kontrol eder.
    Eğer paket kurulu ise, 'apply' fonksiyonunu çağırarak paketi kaldırır.
    """
    # Bu politika kullanıcıya özel değil, sistem geneli olduğu için 'username' kullanılmaz.
    
    package_name = parameters.get("package_name")
    if not package_name:
        return False, "Politika hatası: 'package_name' parametresi ile kaldırılacak paket adı belirtilmemiş."
        
    try:
       success, output = run_command(['dpkg', '-l', package_name])

       if f"ii  {package_name}" in output:
            return apply_package_removal(package_name)
       else:
            return True, f"'{package_name}' paketi zaten sistemde kurulu değil."

    except Exception as e:
        return False, f"Paket durumu kontrol edilirken beklenmedik bir hata oluştu: {e}"


def apply_package_removal(package_name: str) -> tuple[bool, str]:
    """
    Belirtilen paketi yapılandırma dosyalarıyla birlikte sistemden kaldırır ('purge').
    sudo yetkisi gerektirir.
    """
    try:
        print(f"'{package_name}' paketi sistemden kaldırılıyor...")
        # '-y' parametresi tüm onay sorularına otomatik 'evet' yanıtı verir.
        # 'purge' komutu, paketi ve ilgili tüm yapılandırma dosyalarını siler.
        success, output = run_command(
            ['sudo', 'apt-get', 'purge', '-y', package_name]
        )
        if not success:
            return False, f"'{package_name}' paketi kaldırılamadı: {output}. 'sudoers' dosyasını kontrol edin."
        return True, f"'{package_name}' paketi ve yapılandırma dosyaları başarıyla sistemden kaldırıldı."
    except Exception as e:
        return False, f"Paket kaldırılırken genel bir hata oluştu: {e}"
# ==============================================================================