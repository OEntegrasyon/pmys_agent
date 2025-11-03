import os
import tempfile
from utils import run_command;

#---------------------------------------------------------------------------
# Sudo Policies
#---------------------------------------------------------------------------

# Kullanıcıya belirli komutlar için kısıtlı sudo yetkisi ver#

def check_restrict_sudo_commands(username, parameters):
    commands_param = parameters.get("commands", [])
    # Gelen parametrenin tek bir string mi yoksa liste mi olduğunu kontrol et
    if isinstance(commands_param, str):
        commands = [commands_param] 
    else:
        commands = commands_param 

    if not commands:
        return False, "Parametrelerde 'commands' listesi boş olamaz."
        
    config_file_path = f"/etc/sudoers.d/{username}-restricted"
    commands_str = ", ".join(commands)
    expected_content = f"{username} ALL=(ALL) {commands_str}"

    if not os.path.exists(config_file_path):
        return apply_restrict_sudo_commands(username, parameters)

    try:
        with open(config_file_path, 'r') as f:
            current_content = f.read().strip()
        
        if current_content == expected_content:
            return True, f"Kısıtlı sudo yetkileri '{username}' için zaten doğru şekilde uygulanmış."
        else:
            return apply_restrict_sudo_commands(username, parameters)
    except Exception as e:
        return False, f"Sudo yetki dosyası okunurken hata: {e}"

def apply_restrict_sudo_commands(username, parameters):
    commands_param = parameters.get("commands", [])
    if isinstance(commands_param, str):
        commands = [commands_param]
    else:
        commands = commands_param

    config_file_path = f"/etc/sudoers.d/{username}-restricted"
    commands_str = ", ".join(commands)
    content = f"{username} ALL=(ALL) {commands_str}"

    fd, temp_path = tempfile.mkstemp(text=True)
    try:
        with os.fdopen(fd, 'w') as temp_file:
            temp_file.write(content + "\n")

        check_success, check_output = run_command(["sudo", "visudo", "-c", "-f", temp_path])
        if not check_success:
            return False, f"Oluşturulan sudo kuralı sentaks kontrolünü geçemedi: {check_output}"

        move_success, move_output = run_command(["sudo", "mv", temp_path, config_file_path])
        if not move_success:
            return False, f"Doğrulanmış sudo dosyası taşınamadı: {move_output}"
        
        run_command(["sudo", "chown", "root:root", config_file_path])
        run_command(["sudo", "chmod", "0440", config_file_path])
        
        return True, f"Kısıtlı sudo yetkileri '{username}' için başarıyla uygulandı."
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

#"---------------------------------------------------------------------------
# Parolasız Sudo Policies
#---------------------------------------------------------------------------
def check_nopasswd_sudo_commands(username, parameters):
    commands_param = parameters.get("commands", [])
    if isinstance(commands_param, str):
        commands = [commands_param]
    else:
        commands = commands_param


    if not commands:
        return False, "Parametrelerde 'commands' listesi boş olamaz."
        
    config_file_path = f"/etc/sudoers.d/{username}-nopasswd"
    commands_str = ", ".join(commands)
    expected_content = f"{username} ALL=(ALL) NOPASSWD: {commands_str}"

    if not os.path.exists(config_file_path):
        return apply_nopasswd_sudo_commands(username, parameters)
    
    try:
        with open(config_file_path, 'r') as f:
            current_content = f.read().strip()
        
        if current_content == expected_content:
            return True, f"Parolasız sudo yetkileri '{username}' için zaten doğru şekilde uygulanmış."
        else:
            return apply_nopasswd_sudo_commands(username, parameters)
    except Exception as e:
        return False, f"Sudo yetki dosyası okunurken hata: {e}"

def apply_nopasswd_sudo_commands(username, parameters):
    commands_param = parameters.get("commands", [])
    if isinstance(commands_param, str):
        commands = [commands_param]
    else:
        commands = commands_param
    
    config_file_path = f"/etc/sudoers.d/{username}-nopasswd"
    commands_str = ", ".join(commands)
    content = f"{username} ALL=(ALL) NOPASSWD: {commands_str}"

    fd, temp_path = tempfile.mkstemp(text=True)
    try:
        with os.fdopen(fd, 'w') as temp_file:
            temp_file.write(content + "\n")

        check_success, check_output = run_command(["sudo", "visudo", "-c", "-f", temp_path])
        if not check_success:
            return False, f"Oluşturulan NOPASSWD kuralı sentaks kontrolünü geçemedi: {check_output}"

        move_success, move_output = run_command(["sudo", "mv", temp_path, config_file_path])
        if not move_success:
            return False, f"Doğrulanmış NOPASSWD dosyası taşınamadı: {move_output}"
        
        run_command(["sudo", "chown", "root:root", config_file_path])
        run_command(["sudo", "chmod", "0440", config_file_path])
        
        return True, f"Parolasız sudo yetkileri '{username}' için başarıyla uygulandı."
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
#---------------------------------------------------------------------------
#---------------------------------------------------------------------------
# Kullanıcı Yönetim Yetkisi Policies
#---------------------------------------------------------------------------
def check_user_management_privileges(username, parameters):
    config_file_path = f"/etc/sudoers.d/{username}-usermgmt"
    # Bu politikada komutlar sabittir.
    commands = ["/usr/sbin/adduser", "/usr/sbin/deluser"]
    commands_str = ", ".join(commands)
    expected_content = f"{username} ALL=(ALL) {commands_str}"

    if not os.path.exists(config_file_path):
        return apply_user_management_privileges(username, parameters)

    try:
        with open(config_file_path, 'r') as f:
            current_content = f.read().strip()
        
        if current_content == expected_content:
            return True, f"Kullanıcı yönetimi yetkileri '{username}' için zaten doğru şekilde uygulanmış."
        else:
            return apply_user_management_privileges(username, parameters)
    except Exception as e:
        return False, f"Sudo yetki dosyası okunurken hata: {e}"


def apply_user_management_privileges(username, parameters):
    config_file_path = f"/etc/sudoers.d/{username}-usermgmt"
    commands = ["/usr/sbin/adduser", "/usr/sbin/deluser"]
    commands_str = ", ".join(commands)
    content = f"{username} ALL=(ALL) {commands_str}"

    fd, temp_path = tempfile.mkstemp(text=True)
    try:
        with os.fdopen(fd, 'w') as temp_file:
            temp_file.write(content + "\n")

        check_success, check_output = run_command(["sudo", "visudo", "-c", "-f", temp_path])
        if not check_success:
            os.remove(temp_path)
            return False, f"Oluşturulan kullanıcı yönetimi kuralı sentaks kontrolünü geçemedi: {check_output}"

        move_success, move_output = run_command(["sudo", "mv", temp_path, config_file_path])
        if not move_success:
            os.remove(temp_path)
            return False, f"Doğrulanmış kullanıcı yönetimi dosyası taşınamadı: {move_output}"
        
        run_command(["sudo", "chown", "root:root", config_file_path])
        run_command(["sudo", "chmod", "0440", config_file_path])
        
        return True, f"Kullanıcı yönetimi yetkileri '{username}' için başarıyla uygulandı."
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
#---------------------------------------------------------------------------
# Sudo Loglama Policies
#---------------------------------------------------------------------------
def check_sudo_logfile_config(username, parameters):
    """
    /etc/sudoers.d/ altında sudo loglaması için yapılandırma dosyasının
    varlığını ve doğruluğunu kontrol eder.
    """
    config_file_path = "/etc/sudoers.d/01-sudo-logging"
    expected_content = 'Defaults    logfile="/var/log/sudo.log"'

    if not os.path.exists(config_file_path):
        # Yapılandırma dosyası yoksa uygula.
        return apply_sudo_logfile_config(username, parameters)

    try:
        with open(config_file_path, 'r') as f:
            # Dosya içeriğini boşlukları temizleyerek oku.
            current_content = f.read().strip()
        
        if current_content == expected_content:
            # İçerik doğruysa ve log dosyası varsa, politika başarılıdır.
            if os.path.exists("/var/log/sudo.log"):
                 return True, "Sudo log yapılandırması ve log dosyası zaten mevcut."
            else:
                 # Yapılandırma var ama log dosyası silinmiş, yeniden oluştur.
                 return apply_sudo_logfile_config(username, parameters)
        else:
            # İçerik yanlışsa, doğru yapılandırmayı uygula.
            return apply_sudo_logfile_config(username, parameters)
    except Exception as e:
        return False, f"Sudo log yapılandırma dosyası okunurken hata: {e}"

def apply_sudo_logfile_config(username, parameters):
    """
    Sudo loglama kuralını güvenli bir şekilde oluşturur, visudo ile kontrol eder,
    yerine taşır ve log dosyasının kendisini oluşturur.
    """
    config_file_path = "/etc/sudoers.d/01-sudo-logging"
    content = 'Defaults    logfile="/var/log/sudo.log"'
    log_file = "/var/log/sudo.log"

    # Güvenli yazma işlemi için geçici bir dosya oluştur.
    fd, temp_path = tempfile.mkstemp(text=True)
    try:
        # 1. Kuralı geçici dosyaya yaz.
        with os.fdopen(fd, 'w') as temp_file:
            temp_file.write(content + "\n")

        # 2. KRİTİK: visudo ile sentaksı kontrol et.
        check_success, check_output = run_command(["sudo", "visudo", "-c", "-f", temp_path])
        if not check_success:
            os.remove(temp_path)
            return False, f"Oluşturulan sudo log kuralı sentaks kontrolünü geçemedi: {check_output}"

        move_success, move_output = run_command(["sudo", "mv", temp_path, config_file_path])
        if not move_success:
            os.remove(temp_path)
            return False, f"Doğrulanmış sudo log yapılandırma dosyası taşınamadı: {move_output}"
        
        # 4. Yapılandırma dosyasının izinlerini ayarla (sahibi root, izinler 0440).
        run_command(["sudo", "chown", "root:root", config_file_path])
        run_command(["sudo", "chmod", "0440", config_file_path])
        
        # 5. Log dosyasının kendisini oluştur ve izinlerini ayarla.
        run_command(["sudo", "touch", log_file])
        run_command(["sudo", "chmod", "0640", log_file])

        return True, "Sudo log yapılandırması başarıyla uygulandı."
    finally:
        # Her durumda geçici dosyanın silindiğinden emin ol.
        if os.path.exists(temp_path):
            os.remove(temp_path)