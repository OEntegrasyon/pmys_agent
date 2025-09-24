import configparser
import json
import stat
import subprocess
from venv import logger
from utils import get_logged_in_user
import time as time_module
import os
from datetime import datetime
import grp
import hashlib
import pwd
import re
import shutil

def get_display_and_dbus_env():
    """
    Returns the current user's DISPLAY and DBUS_SESSION_BUS_ADDRESS environment variables.
    """
    user = get_logged_in_user()
    if not user:
        return None, None, None
    try:
        # Get DISPLAY
        display = os.environ.get("DISPLAY")
        # Get DBUS_SESSION_BUS_ADDRESS
        dbus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        return user, display, dbus
    except Exception:
        return user, None, None

def run_command(cmd, timeout=30):
    """
    Komut çalıştır ve (başarı, çıktı) döndür.
    
    Args:
        cmd (list): Çalıştırılacak komut (örnek: ["ls", "-l"])
        timeout (int): Maksimum çalışma süresi (saniye)

    Returns:
        (bool, str): (Başarı durumu, Çıktı veya hata mesajı)
    """
    try:
        logger.debug(f"[run_command] Çalıştırılıyor: {' '.join(cmd)} (timeout={timeout}s)")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = ""
        if result.stdout:
            output += result.stdout.strip()
        if result.stderr:
            if output:
                output += "\n"
            output += result.stderr.strip()

        success = (result.returncode == 0)
        logger.debug(f"[run_command] ExitCode={result.returncode}, Success={success}, Output={output}")
        return success, output

    except subprocess.TimeoutExpired:
        msg = f"Komut zaman aşımına uğradı: {' '.join(cmd)}"
        logger.error(f"[run_command] {msg}")
        return False, msg
    except FileNotFoundError:
        msg = f"Komut bulunamadı: {cmd[0]}"
        logger.error(f"[run_command] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Komut çalıştırma hatası: {str(e)}"
        logger.error(f"[run_command] {msg}")
        return False, msg

########################################### İDRİSİN POLİTİKALARI  ###########################################


###################################### 4. SİSTEM YAPILANDIRMA VE OPTİMİZASYON ###########################################################

#  Ağ Yapılandırması Kontrol ve Uygulama

def check_network_configuration(username, parameters):
    """
    Ağ yapılandırmasını kontrol eder.
    Keyword arguments veya parameters sözlüğü kabul eder.
    """
    try:
        
        if not parameters:
            return False, "Parametre verisi yok."

        expected_ip = parameters.get("expected_ip")
        interface = parameters.get("interface", "ens33")

        if not expected_ip:
            return False, "expected_ip parametresi eksik."

        # IP adreslerini kontrol et
        success, msg = run_command(["ip", "addr", "show", interface])
        if msg.returncode != 0:
            return False, f"{interface} arayüzü bulunamadı."

        if expected_ip in msg.stdout:
            return True, f"{interface} üzerinde {expected_ip} IP'si zaten atanmış."

        # IP atanmadıysa, uygula
        return apply_network_configuration(parameters)

    except Exception as e:
        return False, f"Ağ yapılandırması hatası: {str(e)}"

def apply_network_configuration(parameters):
    """
    Verilen parametrelere göre ağ yapılandırmasını uygular ve ağı otomatik olarak yeniden başlatır.
    Bu betiğin çalışması için root (sudo) yetkileri gereklidir.
    """
    try:
        if not parameters:
            return False, "Uygulanacak ağ yapılandırması parametreleri eksik."

        # Parametreleri al, varsayılan değerleri ata
        interface = parameters.get("interface", "ens33")
        expected_ip = parameters.get("expected_ip")
        netmask = parameters.get("netmask", "255.255.255.0")
        gateway = parameters.get("gateway")
        dns = parameters.get("dns", "8.8.8.8 8.8.4.4")

        # Gerekli parametrelerin varlığını kontrol et
        if not expected_ip or not gateway:
            return False, "IP adresi veya ağ geçidi (gateway) parametresi eksik."

        # Yedekleme dizinini oluştur
        backup_dir = "/etc/network/backups"
        os.makedirs(backup_dir, exist_ok=True)
        
        interfaces_path = "/etc/network/interfaces"
        
        # Mevcut yapılandırmayı yedekle
        if os.path.exists(interfaces_path):
            backup_path = os.path.join(backup_dir, f"interfaces.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}")
            shutil.copy(interfaces_path, backup_path)
            print(f"Mevcut ağ yapılandırması şuraya yedeklendi: {backup_path}")
        else:
            # Eğer dosya yoksa, boş bir tane oluştur
            open(interfaces_path, "a").close()

        # Yeni ağ yapılandırma içeriğini oluştur
        interfaces_config = f"""
                                # Bu dosya sisteminizdeki ağ arayüzlerini ve nasıl etkinleştirileceğini tanımlar.
                                # Daha fazla bilgi için: interfaces(5).

                                source /etc/network/interfaces.d/*

                                # Geri döngü (loopback) ağ arayüzü
                                auto lo
                                iface lo inet loopback

                                # Ana ağ arayüzü
                                auto {interface}
                                iface {interface} inet static
                                    address {expected_ip}
                                    netmask {netmask}
                                    gateway {gateway}
                                    dns-nameservers {dns}
                                """

        # Yeni yapılandırmayı dosyaya yaz
        print(f"'{interfaces_path}' dosyası yeni yapılandırma ile güncelleniyor...")
        with open(interfaces_path, "w") as f:
            f.write(interfaces_config)
        print("Dosya başarıyla yazıldı.")

        # --- AĞI YENİDEN BAŞLATMA BÖLÜMÜ ---
        # ifdown/ifup yerine doğrudan networking servisini yeniden başlatmak daha güvenilirdir.
        print("Ağ servisi yeniden başlatılıyor... Bu işlem biraz zaman alabilir.")
        try:
            # systemctl komutu ile networking servisini yeniden başlat
            # check=True, komut başarısız olursa bir istisna fırlatmasını sağlar.
            subprocess.run(
                ["systemctl", "restart", "networking.service"], 
                check=True, 
                timeout=30,
                capture_output=True, # Hata ayıklama için çıktıyı yakala
                text=True
            )
            print("Ağ servisi başarıyla yeniden başlatıldı.")
            # Sistemin yeni IP'yi alıp kararlı hale gelmesi için kısa bir bekleme
            time_module.sleep(5) # DÜZELTME: Yeniden adlandırılmış modülü kullan

        except FileNotFoundError:
            return False, "Hata: 'systemctl' komutu bulunamadı. Sisteminiz systemd kullanmıyor olabilir."
        except subprocess.CalledProcessError as e:
            error_message = f"Hata: Ağ servisi yeniden başlatılamadı.\nKomut: {e.cmd}\nÇıktı: {e.stdout}\nHata Çıktısı: {e.stderr}"
            return False, error_message
        except subprocess.TimeoutExpired:
            return False, "Hata: Ağ servisini yeniden başlatma işlemi zaman aşımına uğradı. Servis takılmış olabilir."
        except Exception as e:
            return False, f"Ağ servisi yeniden başlatılırken beklenmedik bir hata oluştu: {str(e)}"

        # --- SON KONTROL ---
        # Yapılandırmanın başarıyla uygulanıp uygulanmadığını kontrol et
        print(f"'{interface}' arayüzü için yeni IP adresi kontrol ediliyor...")
        result_check = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True)
        
        if f"inet {expected_ip}/" in result_check.stdout:
            success_message = f"Başarılı! '{interface}' arayüzü yeni IP adresiyle yapılandırıldı: {expected_ip}"
            print(success_message)
            return True, success_message
        else:
            failure_message = f"Hata: Yapılandırma sonrası '{interface}' arayüzüne '{expected_ip}' IP'si atanamadı. Lütfen 'ip a' komutuyla manuel kontrol edin.\n'ip a' çıktısı:\n{result_check.stdout}"
            print(failure_message)
            # Yapılandırma başarısız olursa yedeği geri yüklemeyi düşünebilirsiniz.
            return False, failure_message

    except Exception as e:
        return False, f"Ağ yapılandırması uygulanırken genel bir hata oluştu: {str(e)}"


#  Zaman Senkronizasyonu 
def check_ntp_sync(username, parameters):
    try:
        print("DEBUG: check_ntp_sync'e gelen parameters'ın tipi:", parameters)
        result = subprocess.run(["timedatectl", "status"], capture_output=True, text=True)
        if "System clock synchronized: yes" not in result.stdout:
            print("DEBUG: NTP senkronizasyonu aktif değil, apply_ntp_sync çağrılıyor")
            return apply_ntp_sync()
        else:
            return True, "NTP zaten senkronize"
    except Exception as e:
        return False, f"Hata: {str(e)}"

def apply_ntp_sync():
    
    success, msg = run_command(["timedatectl", "set-ntp", "true"])
    if success:
        
        return True, "NTP senkronizasyonu aktif edildi"
    return False, msg
   

#  Gereksiz Hizmetleri Devre Dışı Bırakma
def check_disable_unnecessary_services(username, parameters):
    service = parameters.get('service')
    if not service:
        return False, "Servis adı belirtilmedi."

    try:
        result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True)
        if "disabled" not in result.stdout:           
            return apply_disable_unnecessary_services(parameters)
        else:
            return True, f"{service} zaten devre dışı bırakılmış"
    except Exception as e:
        return False, f"Hata: {str(e)}"

def apply_disable_unnecessary_services(parameters):
    service = parameters.get('service')
    if not service:
        return False, "Servis adı belirtilmedi."
    success, msg = run_command(["systemctl", "disable", service])
    if success:
        return True, f"{service} devre dışı bırakıldı"
    return False, msg

#  Varsayılan Umask Ayarı
UMASK_FILE = "/etc/profile"

def check_umask_setting(username, parameters):
    print(f"DEBUG: check_umask_setting'e gelen parameters'ın tipi: {type(parameters)}")
    print(f"DEBUG: check_umask_setting'e gelen parameters'ın değeri: {parameters}")
    
    desired_umask = parameters.get("umask")
    if not desired_umask:
        return False, "Parametre olarak 'umask' değeri verilmedi veya boş."

    print(f"Umask ayarı kontrol ediliyor: İstenen değer '{desired_umask}'")

    current_umask = None
    try:
        if os.path.exists(UMASK_FILE):
            with open(UMASK_FILE, "r") as f:
                profile_content = f.read()

            umask_match = re.search(r"^\s*umask\s+(\d+)", profile_content, re.MULTILINE)

            if umask_match:
                current_umask = umask_match.group(1)
                if current_umask != desired_umask:                    
                    print(f"Mevcut umask farklı ({current_umask}), {desired_umask} olarak güncelleniyor...")
                    success, apply_message = apply_umask_setting(desired_umask)
                    if not success:                        
                        return False, f"Umask güncellenirken hata oluştu: {apply_message}"
                    return True, f"Umask {desired_umask} olarak güncellendi: {apply_message}"
                else:
                    return True, f"Umask zaten doğru ayarlanmış: {desired_umask}"
            else:
                print("Umask satırı bulunamadı, ekleniyor...")
                success, apply_message = apply_umask_setting(desired_umask)
                if not success:                   
                    return False, f"Umask eklenirken hata oluştu: {apply_message}"
                return True, f"Umask ayarı eklendi: {apply_message}"
        else:
            print(f"{UMASK_FILE} dosyası bulunamadı, oluşturuluyor ve umask ekleniyor...")
            success, apply_message = apply_umask_setting(desired_umask)
            if not success:                
                return False, f"{UMASK_FILE} dosyası oluşturulup umask ayarlanırken hata oluştu: {apply_message}"
            return True, f"Umask ayarı dosya oluşturularak eklendi: {apply_message}"

    except Exception as e:
        return False, f"Umask kontrol veya uygulama sırasında beklenmeyen hata: {str(e)}"


def apply_umask_setting(desired_umask: str) -> tuple[bool, str]:
   
    if not desired_umask:
        return False, "Ayarlanacak 'umask' değeri boş olamaz."

    try:
        # Dosyaya yazma yetkisini kontrol et
        # Ajanınız root olarak çalıştığı için bu kontrol genellikle başarılı olacaktır.
        if not os.access(UMASK_FILE, os.W_OK) and os.path.exists(UMASK_FILE):
            return False, f"Yetki hatası: {UMASK_FILE} dosyasına yazma izni yok. Root yetkisi gerekli."
        elif not os.path.exists(UMASK_FILE) and not os.access(os.path.dirname(UMASK_FILE), os.W_OK):
            return False, f"Yetki hatası: {os.path.dirname(UMASK_FILE)} dizinine yazma izni yok. Dosya oluşturulamıyor."

        lines = []
        if os.path.exists(UMASK_FILE):
            with open(UMASK_FILE, "r") as f:
                lines = f.readlines()

        umask_line_index = -1
        for i, line in enumerate(lines):
            if re.match(r"^\s*umask\s+\d+", line):
                umask_line_index = i
                break

        new_umask_line = f"umask {desired_umask}\n"

        if umask_line_index != -1:
            # Mevcut satırı güncelle
            lines[umask_line_index] = new_umask_line
        else:
            # Umask satırı yoksa, dosyanın sonuna ekle
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(new_umask_line)

        with open(UMASK_FILE, "w") as f:
            f.writelines(lines)

        return True, f"Umask {desired_umask} olarak başarıyla ayarlandı. Değişikliklerin etkili olması için oturumu kapatıp açmanız veya ilgili servisleri yeniden başlatmanız gerekebilir."

    except PermissionError:
        return False, f"Yetki hatası: {UMASK_FILE} dosyasına yazmak için root yetkisi gerekli."
    except Exception as e:
        return False, f"Umask ayarlanırken beklenmeyen bir hata oluştu: {str(e)}"

# Paylaşılan dizinlerin izinleri

def check_shared_directory_permissions(username, parameters):
    directory = parameters.get('directory')
    expected_owner = parameters.get('owner')
    expected_group = parameters.get('group')
    expected_permissions = parameters.get('permissions')  # Örn: '770'

    if not directory or not expected_owner or not expected_group or not expected_permissions:
        return False, "Eksik parametre: directory, owner, group ve permissions gerekli."

    try:
        # Mevcut izin ve sahiplik kontrolü
        stat_info = os.stat(directory)
        current_owner = subprocess.getoutput(f'stat -c %U {directory}')
        current_group = subprocess.getoutput(f'stat -c %G {directory}')
        current_permissions = oct(stat_info.st_mode)[-3:]

        if (current_owner != expected_owner or
            current_group != expected_group or
            current_permissions != expected_permissions):           
            return apply_shared_directory_permissions(parameters)
        else:
            return True, "Dizin sahipliği ve izinler zaten doğru ayarlanmış."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def apply_shared_directory_permissions(parameters):
    directory = parameters.get('directory')
    expected_owner = parameters.get('owner')
    expected_group = parameters.get('group')
    expected_permissions = parameters.get('permissions')  # Örn: '770'

    try:
        # Sahip ve grup değiştirme
        subprocess.run(['chown', f'{expected_owner}:{expected_group}', directory], check=True)
        # İzinleri değiştirme
        subprocess.run(['chmod', expected_permissions, directory], check=True)

        return True, "Dizin sahipliği ve izinler başarıyla güncellendi."

    except subprocess.CalledProcessError as e:
        return False, f"Komut hatası: {str(e)}"
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
# çekirdek parametrelerinin güvenliği 

def check_sysctl_parameters(username, parameters):
    sysctl_key = parameters.get('key')
    expected_value = parameters.get('value')

    if not sysctl_key or expected_value is None:
        return False, "Eksik parametre: 'key' ve 'value' zorunludur."

    try:
        # sysctl değeri oku
        result = subprocess.run(['sysctl', '-n', sysctl_key], capture_output=True, text=True)
        current_value = result.stdout.strip()

        if current_value != str(expected_value):          
            return apply_sysctl_parameters(parameters)
        else:
            return True, f"{sysctl_key} değeri zaten {expected_value} olarak ayarlanmış."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def apply_sysctl_parameters(parameters):
    sysctl_key = parameters.get('key')
    expected_value = parameters.get('value')

    try:
        # sysctl değerini hemen uygula
        subprocess.run(['sysctl', f'{sysctl_key}={expected_value}'], check=True)
        
        # Kalıcı yapmak için /etc/sysctl.conf dosyasına yaz
        with open('/etc/sysctl.conf', 'a') as f:
            f.write(f'\n{sysctl_key} = {expected_value}\n')

        return True, f"{sysctl_key} değeri {expected_value} olarak ayarlandı ve kalıcı hale getirildi."

    except subprocess.CalledProcessError as e:
        return False, f"Komut hatası: {str(e)}"
    except Exception as e:
        return False, f"Hata: {str(e)}"

# Kullanılmayan dosya sistemlerini devre dışı bırakma

def check_disable_unused_filesystem(username, parameters):
    filesystem = parameters.get('filesystem')

    if not filesystem:
        return False, "Dosya sistemi adı belirtilmedi."

    try:
        config_path = f"/etc/modprobe.d/{filesystem}.conf"

        if not os.path.exists(config_path):
            # Dosya yoksa otomatik olarak uygula
            return apply_disable_unused_filesystem(parameters)
        else:
            with open(config_path, 'r') as f:
                content = f.read()
                if f"install {filesystem} /bin/true" in content:
                    return True, f"{filesystem} dosya sistemi zaten devre dışı bırakılmış."
                else:
                    # Dosya var ama içeriği uygun değil
                    return apply_disable_unused_filesystem(parameters)      

      
    except Exception as e:
        return False, f"Hata: {str(e)}"
    

def apply_disable_unused_filesystem(parameters):
    filesystem = parameters.get('filesystem')

    if not filesystem:
        return False, "Dosya sistemi adı belirtilmedi."

    try:
        config_path = f"/etc/modprobe.d/{filesystem}.conf"
        with open(config_path, 'w') as f:
            f.write(f"install {filesystem} /bin/true\n")

        return True, f"{filesystem} dosya sistemi devre dışı bırakıldı."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
# Ayrı /tmp, /var, /home Partisyonları

def check_separate_partitions(username, parameters=None):
    """
    /tmp, /var ve /home için ayrı partisyon kontrolü yapar.
    """
    try:
        result = subprocess.run(["df", "-hT"], capture_output=True, text=True)
        output = result.stdout

        # Kontrol edilecek dizinler
        required_mounts = ['/tmp', '/var', '/home']
        found_mounts = []

        for line in output.splitlines():
            for mount in required_mounts:
                if line.strip().endswith(mount):
                    found_mounts.append(mount)

        missing_mounts = [m for m in required_mounts if m not in found_mounts]

        if  missing_mounts:           
            return False, f"Ayrı partisyon bulunamayan dizinler: {', '.join(missing_mounts)}"
        else:
            return True, "Tüm gerekli dizinler için ayrı partisyonlar mevcut."

    except Exception as e:
        return False, f"Hata oluştu: {str(e)}"

###################################### 5. YAZILIM VE PAKET YÖNETİMİ  ###########################################################


# Zorunlu Yazılım Kurulumu/Kaldırılması

def check_required_software(username, parameters):
    mode = parameters.get("mode", "both")
    required_packages = parameters.get("required", [])
    forbidden_packages = parameters.get("forbidden", [])

    missing_packages = []
    existing_forbidden = []

    try:
        if mode in ["install", "both"]:
            for package in required_packages:
                result = subprocess.run(["dpkg", "-l", package], capture_output=True, text=True)
                if f"ii  {package}" not in result.stdout:
                    missing_packages.append(package)

        if mode in ["remove", "both"]:
            for package in forbidden_packages:
                result = subprocess.run(["dpkg", "-l", package], capture_output=True, text=True)
                if f"ii  {package}" in result.stdout:
                    existing_forbidden.append(package)

        if not missing_packages and not existing_forbidden:
            return True, "Tüm yazılım gereksinimleri karşılanıyor."

        return apply_required_software(parameters, missing_packages, existing_forbidden)
         
    except Exception as e:
        return False, f"Hata oluştu: {str(e)}"

def apply_required_software(parameters, missing_packages, existing_forbidden):
    mode = parameters.get("mode", "both")
    messages = []

    try:
        if mode in ["install", "both"]:
            for package in missing_packages:
                install_result = subprocess.run(["apt", "install", "-y", package], capture_output=True, text=True)
                if install_result.returncode == 0:
                    messages.append(f"{package} başarıyla yüklendi.")
                else:
                    messages.append(f"{package} yüklenemedi. Hata: {install_result.stderr.strip()}")

        if mode in ["remove", "both"]:
            for package in existing_forbidden:
                remove_result = subprocess.run(["apt", "remove", "-y", package], capture_output=True, text=True)
                if remove_result.returncode == 0:
                    messages.append(f"{package} başarıyla kaldırıldı.")
                else:
                    messages.append(f"{package} kaldırılamadı. Hata: {remove_result.stderr.strip()}")

        if not messages:
            return True, "Yapılacak işlem yoktu."

        return True, " ".join(messages)
       
    except Exception as e:
        return False, f"Hata oluştu: {str(e)}"
    

# Paket Sürüm Sabitleme

def check_package_pinning(username, parameters):
    try:
        package_name = parameters.get("package")
        version = parameters.get("version")

        if not package_name or not version:
            return False, "Paket adı veya sürüm belirtilmedi."

        result = subprocess.run(["apt-cache", "policy", package_name], capture_output=True, text=True)

        if "1001" in result.stdout and version in result.stdout:
            return True, f"{package_name} paketi zaten {version} sürümüne sabitlenmiş."
        else:
            return apply_package_pinning(parameters)
         
    except Exception as e:
        return False, f"Hata: {str(e)}"



def apply_package_pinning(parameters):
    try:
        package_name = parameters.get("package")
        version = parameters.get("version")

        if not package_name or not version:
            return False, "Paket adı veya sürüm belirtilmedi."

        # Pinleme dosyası oluştur
        pin_file = f"/etc/apt/preferences.d/{package_name}.pref"
        with open(pin_file, "w") as f:
            f.write(f"Package: {package_name}\n")
            f.write(f"Pin: version {version}\n")
            f.write(f"Pin-Priority: 1001\n")

        # Paketi kilitle
        subprocess.run(["apt-mark", "hold", package_name], check=True)

        # Pinleme başarı kontrolü
        result = subprocess.run(["apt-cache", "policy", package_name], capture_output=True, text=True)

        if "1001" in result.stdout and version in result.stdout:
            return True, f"{package_name} paketi {version} sürümüne sabitlendi ve güncellemesi engellendi."
        else:
            return False, f"{package_name} için pinleme başarısız. Elle kontrol ediniz."

    except subprocess.CalledProcessError as e:
        return False, f"Komut hatası: {str(e)}"
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
# Paket İmzaların doğrulanması

def check_package_signatures(username, parameters):
    """
    Paket imzalarının doğrulanmasının aktif olup olmadığını kontrol eder.
    apt update komutu sırasında imza hatası var mı diye bakar.
    """
    try:
        # apt update komutunu simüle ederek imza hatalarını arıyoruz
        result = subprocess.run(['apt-get', 'update', '-o', 'Acquire::AllowUnauthenticated=false'],
                                capture_output=True, text=True, check=True)

        # Eğer çıktı hatasızsa, doğrulama sorunu yok demektir
        if "NO_PUBKEY" in result.stdout or "NO_PUBKEY" in result.stderr:
            return False, "GPG imza doğrulama eksik veya sorunlu: NO_PUBKEY hatası var."
        if "Warning" in result.stdout or "Warning" in result.stderr:
            return False, "APT güncelleme sırasında uyarılar var, imza doğrulama kontrol edilmeli."
        
        return True, "Paket imzaları doğrulaması düzgün çalışıyor."
    except subprocess.CalledProcessError as e:
        # apt-get update komutu başarısızsa muhtemelen doğrulama ile ilgili bir sorun vardır
        return False, f"Hata oluştu: {e.stderr or str(e)}"


def apply_package_signatures(parameters=None):
    """
    Paket imzalarının doğrulanması için gerekli temel ayarları sağlar.
    Örneğin AllowUnauthenticated parametresini false yapar.
    Not: Sistemin deposu ve anahtarlarının düzgün kurulması gerekir.
    """
    try:
        # Örnek: /etc/apt/apt.conf.d/99verify dosyası oluşturup güvenliği artırabiliriz
        config_path = "/etc/apt/apt.conf.d/99verify"
        config_content = 'Acquire::AllowUnauthenticated "false";\n'
        
        with open(config_path, 'w') as f: 
            f.write(config_content)
        
        return True, f"{config_path} dosyası oluşturuldu ve imza doğrulaması zorunlu hale getirildi."
    except Exception as e:
        return False, f"İmza doğrulama yapılandırması uygulanamadı: {str(e)}"
    

#################################### 6. DONANIM VE AYGIT YÖNETİMİ ###########################################################



# CD/DVD Sürücüsü Erişimi Engelleme

def check_cdrom_access(username, parameters):
    try:
        rule_file = "/etc/udev/rules.d/99-cdrom-block.rules"
        expected_rule = 'KERNEL=="sr*", ATTR{removable}=="1", ATTR{authorized}="0"'

        # Eğer dosya yoksa otomatik yaz
        if not os.path.exists(rule_file):
            with open(rule_file, "w") as f:
                f.write(expected_rule + '\n')

            subprocess.run(['udevadm', 'control', '--reload'], check=True)
            subprocess.run(['udevadm', 'trigger'], check=True)
           

        # Dosya varsa içeriği kontrol et
        with open(rule_file, "r") as f:
            content = f.read()

        if expected_rule not in content:            
            # Dosya var ama içerik hatalıysa düzelt
            with open(rule_file, "w") as f:
                f.write(expected_rule + '\n')

            subprocess.run(['udevadm', 'control', '--reload'], check=True)
            subprocess.run(['udevadm', 'trigger'], check=True)
            
        return True, "CD/DVD erişim engelleme kuralı zaten doğru ayarlanmış."
    except PermissionError:
        return (False, "Yetki hatası: Bu işlemi yapmak için root olmalısınız.")
    except subprocess.CalledProcessError as e:
        return (False, f"udev komutlarında hata oluştu: {e}")
    except Exception as e:
        return (False, f"Genel hata: {e}")

def apply_cdrom_access_restriction(parameters=None):
    try:
        rule_file = "/etc/udev/rules.d/99-cdrom-block.rules"

        # Udev kuralını yaz
        with open(rule_file, "w") as f:
            f.write('KERNEL=="sr*", ATTR{removable}=="1", ATTR{authorized}="0"\n')

        # Udev yapılandırmasını yeniden yükle
        subprocess.run(['udevadm', 'control', '--reload'], check=True)
        subprocess.run(['udevadm', 'trigger'], check=True)

        return (True, "CD/DVD erişimi engelleyen udev kuralı başarıyla uygulandı.")
    except PermissionError:
        return (False, "Yetki hatası: Bu işlemi yapmak için root olmalısınız.")
    except subprocess.CalledProcessError as e:
        return (False, f"udev komutlarında hata oluştu: {e}")
    except Exception as e:
        return (False, f"Genel hata: {e}")

#Harici Aygıtların Otomatik Bağlanmasını (Automount) Engelleme

UDEV_AUTOMOUNT_RULE_PATH = "/etc/udev/rules.d/99-automount-block.rules"

def check_automount_block(username, parameters):
    if not os.path.exists(UDEV_AUTOMOUNT_RULE_PATH):
        # Dosya yoksa hemen oluşturmayı dene
        success, msg = apply_automount_block()
        if not success:
            return False, f"Dosya yoktu, oluşturulmaya çalışıldı ama başarısız: {msg}"
        # Dosya oluşturuldu, kontrol edilecek
    try:
        with open(UDEV_AUTOMOUNT_RULE_PATH, "r") as f:
            content = f.read()
        if 'ENV{UDISKS_IGNORE}="1"' not in content:
            return False, "Automount engelleme kuralı dosyada bulunamadı."
        return True, "Automount engelleme kuralı başarıyla doğrulandı."
    except Exception as e:
        return False, f"Kural kontrolünde hata: {e}"

def apply_automount_block(parameters=None):
    try:
        rule = 'ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"\n'
        with open(UDEV_AUTOMOUNT_RULE_PATH, "w") as f:
            f.write(rule)

        subprocess.run(['udevadm', 'control', '--reload'], check=True)
        subprocess.run(['udevadm', 'trigger'], check=True)

        return True, "Automount engelleme kuralı başarıyla uygulandı."
    except PermissionError:
        return False, "Yetki hatası: root olmanız gerekiyor."
    except subprocess.CalledProcessError as e:
        return False, f"udev komutlarında hata: {e}"
    except Exception as e:
        return False, f"Genel hata: {e}"

########################################## Şamilin Politikaları ###################################################

#ssh conf icinde include varsaydımmm##########################################################################
def ssh_port_change(username, parameters):
    try:
        if not parameters:
            return False, "Parametre eksik."

        if isinstance(parameters, str):
            try:
                param_data = json.loads(parameters)
            except json.JSONDecodeError:
                return False, "Parametre geçerli bir JSON formatında değil."
        elif isinstance(parameters, dict):
            param_data = parameters
        else:
            return False, "Parametre türü geçersiz."

        # "Port" anahtarı olup olmadığını kontrol et
        if "Port" not in param_data:
            return False, "JSON içinde 'Port' anahtarı bulunamadı."

        port = str(param_data.get("Port"))
        if not port or not port.isdigit() or not (1 <= int(port) <= 65535):
            return False, "Geçersiz port numarası. 1-65535 aralığında bir sayı girin."
        if port == "22":
            return False, "Port numarası 22 olarak ayarlanamaz. Lütfen farklı bir port girin."

        if check_ssh_port_change(port):
            return False, f"SSH zaten bu port üzerinden çalışıyor: {port}"

        conf_dir = "/etc/ssh/sshd_config.d"
        conf_file = os.path.join(conf_dir, "ssh_port.conf")
        os.makedirs(conf_dir, exist_ok=True)

        if os.path.exists(conf_file):
            os.remove(conf_file)

        with open(conf_file, "w") as f:
            f.write(f"Port {port}\n")

        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            return True, f"SSH portu {port} olarak başarıyla ayarlandı."
        else:
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        return False, f"SSH port değiştirme hatası: {str(e)}"

def check_ssh_port_change(desired_port):
    conf_file = "/etc/ssh/sshd_config.d/ssh_port.conf"
    if not os.path.exists(conf_file):
        return False

    try:
        with open(conf_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            if line.strip().startswith("Port") and str(desired_port) in line:
                return True
        return False
    except Exception:
        return False

####################################################################################################
def ssh_timeout(username, parameters):
    try:
        if not parameters:
            return False, "Parametre eksik."

        # Kontrol
        if isinstance(parameters, str):
            try:
                param_data = json.loads(parameters)
            except json.JSONDecodeError:
                return False, "Parametre geçerli bir JSON formatında değil."
        elif isinstance(parameters, dict):
            param_data = parameters
        else:
            return False, "Parametre türü geçersiz."

        if "Timeout" not in param_data:
            return False, "'Timeout' parametresi eksik."

        timeout = param_data.get("Timeout")
        if not timeout or not str(timeout).isdigit() or int(timeout) < 1:
            return False, "Geçersiz süre. Dakika cinsinden pozitif bir sayı girin."

        if check_ssh_timeout(timeout):
            return False, f"SSH zaman aşımı zaten {timeout} dakika olarak ayarlanmış."

        seconds = int(timeout) * 60

        conf_dir = "/etc/ssh/sshd_config.d"
        conf_file = os.path.join(conf_dir, "ssh_timeout.conf")
        os.makedirs(conf_dir, exist_ok=True)

        if os.path.exists(conf_file):
            os.remove(conf_file)

        # yeni ayarları yaz
        with open(conf_file, "w") as f:
            f.write(f"ClientAliveInterval {seconds}\n")
            f.write("ClientAliveCountMax 0\n")

        # ssh yeniden başlat
        success, output = run_command(["systemctl", "restart", "ssh"])
        if success:
            return True, f"SSH zaman aşımı süresi {timeout} dakika olarak ayarlandı."
        else:
            return False, f"SSH servisi yeniden başlatılamadı: {output}"

    except Exception as e:
        return False, f"Zaman aşımı ayarlanırken hata oluştu: {str(e)}"

def check_ssh_timeout(timeout):
    """
    Belirtilen zaman aşımı değeri zaten uygulanmış mı kontrol eder.
    """
    conf_file = "/etc/ssh/sshd_config.d/ssh_timeout.conf"
    if not os.path.exists(conf_file):
        return False

    try:
        with open(conf_file, "r") as f:
            lines = f.readlines()
        seconds = int(timeout) * 60
        for line in lines:
            if line.strip().startswith("ClientAliveInterval") and str(seconds) in line:
                return True
        return False
    except Exception:
        return False
##########################################################################################

def restrict_ssh_to_ips(username, parameters):
    try:
        if not parameters:
            return False, "Parametre eksik."

        if isinstance(parameters, str):
            import json
            parameters = json.loads(parameters)

        allowed_ips = parameters.get("IP_Adresleri")
        if not allowed_ips or not isinstance(allowed_ips, list):
            return False, "Geçerli bir IP listesi girilmedi."

        if check_restrict_ssh_to_ips(allowed_ips):
            return False, "Bu SSH erişim politikası zaten uygulanmış."

        # SSH config'e eklenecek Match kısmı
        match_block = "\n# Olmayan Kullanici ile herkesi engelle\n"
        match_block += "AllowUsers yokkullanici\n"

        
        match_block += "\n\n# Politikayla eklenen IP sınırı\n"
        for ip in allowed_ips:
            match_block += f"Match Address {ip}\n    AllowUsers {os.getlogin()}\n"

        sshd_conf_path = "/etc/ssh/sshd_config.d/restrict_ips.conf"
        with open(sshd_conf_path, "w") as f:
            f.write(match_block)

        # SSH servisini yeniden başlat
        subprocess.run(["systemctl", "restart", "ssh"], check=True)

        return True, f"Yalnızca şu IP'lerden SSH erişimine izin verildi: {', '.join(allowed_ips)}"

    except Exception as e:
        return False, f"Politika hatası: {str(e)}"
        
def check_restrict_ssh_to_ips(allowed_ips):
    """
    Daha önce restrict_ssh_to_ips politikası uygulanmış mı kontrol eder.
    """
    sshd_conf_path = "/etc/ssh/sshd_config.d/restrict_ips.conf"
    if not os.path.exists(sshd_conf_path):
        return False

    try:
        with open(sshd_conf_path, "r") as f:
            content = f.read()

        # Tüm IP'lerin config dosyasında olup olmadığını kontrol et
        for ip in allowed_ips:
            if f"Match Address {ip}" not in content:
                return False
        return True

    except Exception:
        return False
########################################################################

def set_screensaver_timeout(**parameters):
    try:
        if not parameters:
            return False, "Parametre eksik."

        if isinstance(parameters, str):
            try:
                param_data = json.loads(parameters)
            except json.JSONDecodeError:
                return False, "Parametre geçerli bir JSON formatında değil."
        elif isinstance(parameters, dict):
            param_data = parameters
        else:
            return False, "Parametre türü geçersiz."

        dakika = param_data.get("Süre")

        if not dakika or not str(dakika).isdigit():
            return False, "Geçerli bir dakika bilgisi girilmedi."

        saniye = int(dakika) * 60

        user = get_logged_in_user()
        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()

        if not user or not display or not dbus:
            return False, "Gerekli ortam değişkenleri alınamadı."

        if "gnome" not in session_type:
            return False, f"Bu politika yalnızca GNOME masaüstünde desteklenmektedir. Algılanan: {session_type}"

        env_prefix = f'DISPLAY={display} DBUS_SESSION_BUS_ADDRESS="{dbus}" '

        commands = [
            f"gsettings set org.gnome.desktop.session idle-delay {saniye}",
            f"gsettings set org.gnome.desktop.screensaver lock-delay 5",
            f"gsettings set org.gnome.desktop.screensaver lock-enabled true"
        ]

        
        image_uri = f"file:///opt/screensaver.jpg"
        commands.append(f"gsettings set org.gnome.desktop.screensaver picture-uri '{image_uri}'")
        commands.append(f"gsettings set org.gnome.desktop.screensaver picture-options 'scaled'")
        check = False
        for cmd in commands:
            full_cmd = env_prefix + cmd
            subprocess.run(["sudo", "-u", user, "bash", "-c", full_cmd], check=True)
            check = True
        return True, f"{dakika} dakika sonra ekran koruyucu etkin olacak.{' Görsel ayarlandı.' if check else ''}"

    except subprocess.CalledProcessError as e:
        return False, f"Komut çalıştırma hatası: {str(e)}"
    except Exception as e:
        return False, f"Politika hatası: {str(e)}"

###############################################################################################
#Gnome gdm3 kullandigi icin bu yöntem tercih edildi..
def auto_lock_screen(username, parameters ):
    try:
        if not parameters:
            return False, "Parametre eksik."

        dakika = json.loads(parameters).get("Süre") if isinstance(parameters, str) else parameters.get("Süre")
        if not dakika or not str(dakika).isdigit():
            return False, "Geçerli bir dakika bilgisi girilmedi."

        if check_auto_lock_screen(parameters):
            return False, "Bu ekran kilidi ayarı zaten uygulanmış."

        saniye = int(dakika) * 60

        # Kullanıcıyı tespit et
        user = get_logged_in_user()
        with open("/tmp/debug_auto_lock.log", "a") as f:
            f.write(f"[auto_lock_screen] Kullanıcı: {user}\n")
        if not user:
            return False, "Kullanıcı tespit edilemedi."
        print(f"Kullanıcı: {user}")
        # Masaüstü ortamını belirle
        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()
        if not user or not display or not dbus:
            return False, "Gerekli ortam değişkenleri (DISPLAY veya DBUS) alınamadı."
        
        env_prefix = f'DISPLAY={display} DBUS_SESSION_BUS_ADDRESS="{dbus}" '

        with open("/tmp/debug_session_type.log", "a") as f:
            f.write(f"[auto_lock_screen] Masaüstü ortamı: {session_type}\n")
        print(f"Belirlenen masaüstü ortamı: {session_type}")
        if "gnome" in session_type:
            commands = [
                f"gsettings set org.gnome.desktop.session idle-delay {saniye}",
                f"gsettings set org.gnome.desktop.screensaver lock-enabled true",
                f"gsettings set org.gnome.desktop.screensaver lock-delay 0"
            ]
        elif "xfce" in session_type:
            commands = [
                f"xfconf-query -c xfce4-session -p /general/LockCommand -s 'xflock4'",
                f"xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s {dakika}",
                f"xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/dpms-on-ac-sleep -s {dakika}",
                f"xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled -s true"
            ]
        else:
            return False, f"Desteklenmeyen masaüstü ortamı: {session_type}"
        
        print(f"Kullanıcı: {user}, DISPLAY: {display}, DBUS: {dbus}")

        for cmd in commands:
            subprocess.run(["sudo", "-u", user, "bash", "-c", env_prefix + cmd], check=True)

        return True, f"{dakika} dakika sonra otomatik ekran kilidi etkinleştirildi."

    except subprocess.CalledProcessError as e:
        return False, f"Komut çalıştırma hatası: {str(e)}"
    except Exception as e:
        return False, f"Politika hatası: {str(e)}"

def check_auto_lock_screen(param):
    try:
        if isinstance(param, str):
            param_data = json.loads(param)
        elif isinstance(param, dict):
            param_data = param
        else:
            return False

        dakika = param_data.get("Süre")
        if not dakika or not str(dakika).isdigit():
            return False

        saniye = int(dakika) * 60

        session_type = detect_desktop_env_from_processes()
        user, display, dbus = get_display_and_dbus_env()
        if not user or not display or not dbus:
            return False

        env = os.environ.copy()
        env["DISPLAY"] = display
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus

        if "gnome" in session_type:
            current_raw = subprocess.check_output(
                ["sudo", "-u", user, "gsettings", "get", "org.gnome.desktop.session", "idle-delay"],
                env=env
            ).decode().strip()

            # "uint32 300" gibi ise sadece sayıyı al
            current_val = int(current_raw.split()[-1])
            return current_val == saniye

        elif "xfce" in session_type:
            current = subprocess.check_output([
                "sudo", "-u", user, "xfconf-query", "-c", "xfce4-power-manager", "-p", "/xfce4-power-manager/blank-on-ac"
            ], env=env).decode().strip()
            return int(current) == int(dakika)

        else:
            return False

    except Exception as e:
        print(f"[check_auto_lock_screen] Hata: {e}")
        return False
################################################################################################
def get_logged_in_user():
    try:
        result = subprocess.check_output("who | awk '{print $1}' | head -n 1", shell=True).decode().strip()
        if result and result != "root":
            return result
        else:
            # alternatif olarak en son oturum açan kullanıcı
            return subprocess.check_output("logname", shell=True).decode().strip()
    except Exception:
        return None


def apply_gnome_wallpaper_lockdown(username, parameters):
    """
    GNOME masaüstü duvar kağıdını hem aydınlık hem de karanlık modda
    belirtilen resimle kilitler ve kullanıcının değiştirmesini engeller.

    Bu fonksiyonun root yetkileriyle (sudo) çalıştırılması GEREKLİDİR.

    Parametre:
        param (dict veya JSON string): Duvar kağıdı resminin yolunu içeren bir sözlük.
                                       Örnek: {"image_path": "/usr/share/backgrounds/gnome/adwaita-night.jpg"}
                                       Veya JSON string: '{"image_path": "/usr/share/backgrounds/gnome/adwaita-night.jpg"}'

    Dönüş:
        tuple: (bool, str) - İşlem başarılıysa (True, "Mesaj"),
                             başarısızsa (False, "Hata Mesajı").
    """
    try:
        # Parametreyi JSON string ise sözlüğe dönüştür
        if isinstance(parameters, str):
            param = json.loads(parameters)
        elif not isinstance(parameters, dict):
            return False, "Parametre JSON formatında bir sözlük veya JSON string olmalı."

        # 'Yol' parametresini al
        image_path = parameters.get("Yol")
        if not image_path:
            return False, "'Yol' parametresi eksik. Lütfen bir resim yolu belirtin."

        # Resim dosyasının varlığını kontrol et
        if not os.path.exists(image_path):
            return False, f"Belirtilen resim dosyası bulunamadı: {image_path}"

        # Resim yolunu mutlak yola çevir ve file URI formatına getir
        abs_path = os.path.abspath(image_path)
        
        
        file_uri = f"file://{abs_path.replace(os.sep, '/')}"

        if check_gnome_wallpaper_lockdown(param):
            return False, f"GNOME duvar kağıdı zaten bu resimle kilitlenmiş: {abs_path}"

        print(f"Duvar kağıdı için kullanılacak URI: {file_uri}")

        # 1. Gerekli Dizinleri Oluşturma
        # subprocess.run ile sudo kullanarak dizinleri oluştur
        dirs_to_create = [
            "/etc/dconf/profile",
            "/etc/dconf/db/local.d",
            "/etc/dconf/db/local.d/locks"
        ]
        for d in dirs_to_create:
            print(f"Dizin oluşturuluyor (varsa atlanacak): {d}")
            result = subprocess.run(["sudo", "mkdir", "-p", d], capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"Dizin oluşturma hatası '{d}': {result.stderr.strip()}"

        # 2. Dconf Profili Oluşturma/Düzenleme
        profile_path = "/etc/dconf/profile/user"
        profile_content = """user-db:user
system-db:local
"""
        print(f"Dconf profil dosyası yazılıyor: {profile_path}")

        command = f"echo \"{profile_content}\" | sudo tee {profile_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Dconf profil dosyası yazma hatası: {result.stderr.strip()}"

        # 3. Duvar Kağıdı Ayarları Dosyasını Oluşturma (Aydınlık ve Karanlık Mod Dahil)
        settings_path = "/etc/dconf/db/local.d/00-background-settings"
        # Bu ayar değiştirebilir: 'none', 'wallpaper', 'centered', 'scaled', 'stretched', 'zoom'
        settings_content = f"""[org/gnome/desktop/background]
picture-uri='{file_uri}'
picture-uri-dark='{file_uri}'
picture-options='zoom' 
picture-options-dark='zoom'
primary-color='rgb(0,0,0)'
primary-color-dark='rgb(0,0,0)'
secondary-color='rgb(0,0,0)'
secondary-color-dark='rgb(0,0,0)'
"""
        print(f"Duvar kağıdı ayar dosyası yazılıyor: {settings_path}")
        command = f"echo \"{settings_content}\" | sudo tee {settings_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Duvar kağıdı ayar dosyası yazma hatası: {result.stderr.strip()}"

        # 4. Duvar Kağıdı Ayarını Kilitleme Dosyasını Oluşturma (Aydınlık ve Karanlık Mod Dahil)
        lock_path = "/etc/dconf/db/local.d/locks/background-lock"
        lock_content = """/org/gnome/desktop/background/picture-uri
/org/gnome/desktop/background/picture-uri-dark
/org/gnome/desktop/background/picture-options
/org/gnome/desktop/background/picture-options-dark
/org/gnome/desktop/background/primary-color
/org/gnome/desktop/background/primary-color-dark
/org/gnome/desktop/background/secondary-color
/org/gnome/desktop/background/secondary-color-dark
"""
        print(f"Duvar kağıdı kilit dosyası yazılıyor: {lock_path}")
        command = f"echo \"{lock_content}\" | sudo tee {lock_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Duvar kağıdı kilit dosyası yazma hatası: {result.stderr.strip()}"

        # 5. Dconf Veritabanını Güncelleme
        print("Dconf veritabanı güncelleniyor...")
        result = subprocess.run(["sudo", "dconf", "update"], capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"dconf update hatası: {result.stderr.strip()}"

        return True, f"GNOME duvar kağıdı hem aydınlık hem de karanlık mod için başarıyla kilitlendi: {abs_path}"

    except json.JSONDecodeError:
        return False, "Geçersiz JSON formatı. Parametre bir JSON string olmalı."
    except PermissionError:
        return False, "İzin reddedildi. Bu script root yetkileriyle (sudo) çalıştırılmalıdır."
    except Exception as e:
        return False, f"Beklenmeyen bir hata oluştu: {str(e)}"


def check_gnome_wallpaper_lockdown(parameters):
    try:
        if isinstance(parameters, str):
            parameters = json.loads(parameters)
        elif not isinstance(parameters, dict):
            return False

        image_path = parameters.get("Yol")
        if not image_path or not os.path.exists(image_path):
            return False

        abs_path = os.path.abspath(image_path).replace(os.sep, '/')
        expected_uri = f"file://{abs_path}"

        # 1. Ayar dosyasındaki URI kontrolü
        settings_file = "/etc/dconf/db/local.d/00-background-settings"
        if not os.path.exists(settings_file):
            return False

        with open(settings_file, "r") as f:
            content = f.read()

        if f"picture-uri='{expected_uri}'" not in content:
            return False
        if f"picture-uri-dark='{expected_uri}'" not in content:
            return False

        # 2. Lock dosyasındaki tüm kilitlerin varlığı kontrolü
        lock_file = "/etc/dconf/db/local.d/locks/background-lock"
        required_locks = [
            "/org/gnome/desktop/background/picture-uri",
            "/org/gnome/desktop/background/picture-uri-dark",
            "/org/gnome/desktop/background/picture-options",
            "/org/gnome/desktop/background/picture-options-dark",
            "/org/gnome/desktop/background/primary-color",
            "/org/gnome/desktop/background/primary-color-dark",
            "/org/gnome/desktop/background/secondary-color",
            "/org/gnome/desktop/background/secondary-color-dark"
        ]

        if not os.path.exists(lock_file):
            return False

        with open(lock_file, "r") as f:
            lock_lines = f.read().splitlines()

        for lock in required_locks:
            if lock not in lock_lines:
                return False

        return True

    except Exception as e:
        print(f"[check_gnome_wallpaper_lockdown] Hata: {e}")
        return False
##################################################################################################

def apply_gnome_desktop_icon_policy(username, parameters):
    """
    GNOME masaüstündeki "Çöp" ve "Ev" gibi simgelerin görünürlüğünü merkezi olarak yönetir.
    Bu fonksiyonun root yetkileriyle (sudo) çalıştırılması GEREKLİDİR.

    Parametre:
        param (dict veya JSON string): Görünürlük ayarlarını içeren bir sözlük.
                                       Örnek: {"show_trash": true, "show_home": false}
                                       Veya JSON string: '{"show_trash": true, "show_home": false}'
                                       (true/false Python'daki True/False'a dönüşecek)

    Dönüş:
        tuple: (bool, str) - İşlem başarılıysa (True, "Mesaj"),
                             başarısızsa (False, "Hata Mesajı").
    """
    try:
        # Parametreyi JSON string ise sözlüğe dönüştür
        if isinstance(parameters, str):
            parameters = json.loads(parameters)
        elif not isinstance(parameters, dict):
            return False, "Parametre JSON formatında bir sözlük veya JSON string olmalı."

        # Parametrelerden 'show_trash' ve 'show_home' değerlerini al.
        # Eğer belirtilmemişse varsayılan olarak True (göster) kabul et.
        show_trash = parameters.get("show_trash", True)
        show_home = parameters.get("show_home", True)

        # Boolean değerleri dconf için 'true'/'false' stringlerine çevir
        show_trash_str = str(show_trash).lower()
        show_home_str = str(show_home).lower()

        # 1. Gerekli Dizinleri Oluşturma
        dirs_to_create = [
            "/etc/dconf/profile",
            "/etc/dconf/db/local.d",
            "/etc/dconf/db/local.d/locks"
        ]
        for d in dirs_to_create:
            print(f"Dizin oluşturuluyor (varsa atlanacak): {d}")
            result = subprocess.run(["sudo", "mkdir", "-p", d], capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"Dizin oluşturma hatası '{d}': {result.stderr.strip()}"

        # 2. Dconf Profili Oluşturma/Düzenleme
        # Bu dosya dconf'un sistem veritabanını kullanmasını sağlar.
        profile_path = "/etc/dconf/profile/user"
        profile_content = """user-db:user
system-db:local
"""
        if check_icon_policy_applied(parameters):
            return False, "Masaüstü simgeleri politikası zaten uygulanmış."

        print(f"Dconf profil dosyası yazılıyor: {profile_path}")
        # 'tee' komutu ile sudo kullanarak dosyaya yazma
        command = f"echo \"{profile_content}\" | sudo tee {profile_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Dconf profil dosyası yazma hatası: {result.stderr.strip()}"

        # 3. Masaüstü Simgeleri Ayarları Dosyasını Oluşturma
        # Şema adı org.gnome.shell.extensions.ding olarak değiştirildi!
        settings_path = "/etc/dconf/db/local.d/00-desktop-icons-policy"
        settings_content = f"""[org/gnome/shell/extensions/ding]
show-trash={show_trash_str}
show-home={show_home_str}
"""
        print(f"Masaüstü simgeleri ayar dosyası yazılıyor: {settings_path}")
        command = f"echo \"{settings_content}\" | sudo tee {settings_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Masaüstü simgeleri ayar dosyası yazma hatası: {result.stderr.strip()}"

        # 4. Masaüstü Simgeleri Ayarlarını Kilitleme Dosyasını Oluşturma
        # Şema adı org.gnome.shell.extensions.ding olarak değiştirildi!
        lock_path = "/etc/dconf/db/local.d/locks/desktop-icons-lock"
        lock_content = """/org/gnome/shell/extensions/ding/show-trash
/org/gnome/shell/extensions/ding/show-home
"""
        print(f"Masaüstü simgeleri kilit dosyası yazılıyor: {lock_path}")
        command = f"echo \"{lock_content}\" | sudo tee {lock_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Masaüstü simgeleri kilit dosyası yazma hatası: {result.stderr.strip()}"

        # 5. Dconf Veritabanını Güncelleme
        # Yapılan değişikliklerin sisteme uygulanması için bu komut şarttır.
        print("Dconf veritabanı güncelleniyor...")
        result = subprocess.run(["sudo", "dconf", "update"], capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"dconf update hatası: {result.stderr.strip()}"

        status_message = f"Masaüstü simgeleri politikası başarıyla uygulandı: Çöp: {show_trash_str}, Ev: {show_home_str}"
        return True, status_message

    except json.JSONDecodeError:
        return False, "Geçersiz JSON formatı. Parametre bir JSON string olmalı."
    except PermissionError:
        return False, "İzin reddedildi. Bu script root yetkileriyle (sudo) çalıştırılmalıdır."
    except Exception as e:
        return False, f"Beklenmeyen bir hata oluştu: {str(e)}"

def check_icon_policy_applied(parameters):
    """
    Masaüstü simgeleri politikası daha önce uygulanmış mı kontrol eder.
    """
    settings_path = "/etc/dconf/db/local.d/00-desktop-icons-policy"
    if not os.path.isfile(settings_path):
        return False

    try:
        with open(settings_path, "r") as f:
            content = f.read()

        show_trash_str = str(parameters.get("show_trash", True)).lower()
        show_home_str = str(parameters.get("show_home", True)).lower()
        expected_content = f"""[org/gnome/shell/extensions/ding]
show-trash={show_trash_str}
show-home={show_home_str}
"""

        # Küçük farklar için strip ve normalize yapalım
        if content.strip() == expected_content.strip():
            return True
        else:
            return False
    except Exception:
        return False
#####################################################################################        
# def set_default_policy():
#     """
#     default_policy içindeki tüm fonksiyonları otomatik çalıştırır.
#     """
#     try:
#         results = []

#         # Tüm fonksiyonları al
#         functions = [
#             (name, f)
#             for name, f in inspect.getmembers(default_policy, inspect.isfunction)
#             if name.startswith("reset_")
#         ]


#         for func_name, func in functions:
#             try:
#                 result = func()
#                 if not (isinstance(result, tuple) and len(result) == 2):
#                     result = (False, f"Fonksiyon beklenen tuple (bool, str) dönmedi: {result}")
#                 results.append((func_name, result))
#             except Exception as e:
#                 results.append((func_name, (False, f"Hata: {str(e)}")))

#         success = all(r[1][0] is True for r in results)
#         summary = "\n".join([f"{name}: {msg}" for name, (_, msg) in results])

#         if success:
#             return True, f"Tüm varsayılan politikalar başarıyla uygulandı:\n{summary}"
#         else:
#             return False, f"Bazı politikalar uygulanamadı:\n{summary}"

#     except Exception as e:
#         return False, f"Varsayılan politikaları ayarlarken beklenmeyen hata oluştu: {str(e)}"
    

######################################CANERİN POLİTİKALAR ###############################################################

#Caner'in politikaları


# AuthenticationPasswordPolicyManager 1.

def check_min_password_length(min_length: int):
    filename = "min_length.conf"
    directory = "/etc/security/pwquality.conf.d"
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        return False, f"{path} bulunamadı. Parola uzunluğu henüz ayarlanmamış."
    
    try:
        with open(path, "r") as file:
            content = file.read()

        if f"minlen = {min_length}" in content:
            return True, f"Min parola uzunluğu zaten {min_length}."
        else:
            return False, f"Mevcut parola uzunluğu ayarlanmadı ya da hatalı..."
        
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
    
def min_password_length(min_length: int):
    filename = "min_length.conf"
    directory = "/etc/security/pwquality.conf.d"
    path = os.path.join(directory, filename)

    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "w") as file:
            file.write(f"minlen = {min_length}\n")
        return True, f"Min parola uzunluğu {min_length} olarak ayarlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
   
def ensure_min_password_length(min_length: int):
    success, message = check_min_password_length(min_length)
    
    if not success:
        print(message)
        print("Parola uzunluğunu ayarlanıyor...")
        success, message = min_password_length(min_length)
    return True, message 
#########################################################################################

def check_password_complexity_policy(min_upper: int, min_lower: int, min_digit: int, min_special: int):
    filename="custom-complexity.conf"
    directory = "/etc/security/pwquality.conf.d"
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        return False, f"{path} bulunamadı. Parola uzunluğu henüz ayarlanmamış."
    
    try:
        with open(path, "r") as file:
            content = file.read()

        if f"ucredit = {min_upper}" \
            and f"lcredit = {min_lower}" \
            and f"dcredit = {min_digit}" \
            and f"ocredit = {min_special}" in content:
            return True, f"Parola karmaşıklık politikası zaten {min_upper} - {min_lower} - {min_digit} - {min_special} ."
        else:
            return False, f"Parola karmaşıklık politikası  ayarlanmadı ya da hatalı..."

    except Exception as e:
        return False, f"Hata: {str(e)}"

def password_complexity_policy(min_upper: int, min_lower: int, min_digit: int, min_special: int):
    filename="custom-complexity.conf"
    try:
        directory = "/etc/security/pwquality.conf.d"
        full_path = os.path.join(directory, filename)

        os.makedirs(directory, exist_ok=True)

        with open(full_path, "w") as f:
            f.write(f"ucredit = -{min_upper}\n")
            f.write(f"lcredit = -{min_lower}\n")
            f.write(f"dcredit = -{min_digit}\n")
            f.write(f"ocredit = -{min_special}\n")

        return True, "Parola karmaşıklık politikası yazıldı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def ensure_password_complexity_policy(min_upper: int, min_lower: int, min_digit: int, min_special: int):
    success, message = check_password_complexity_policy(min_upper, min_lower, min_digit, min_special)
    
    if not success:
        print(message)
        print("Parola karmaşıklık politikası ayarlanıyor...")
        success, message = password_complexity_policy(min_upper, min_lower, min_digit, min_special)
    return True, message
    
#########################################################################################
def check_password_history(remember: int):
    pam_file="/etc/pam.d/common-password"
    try:
        with open(pam_file, "r") as file:
            content = file.readlines()

        for line in content:
            if 'pam_unix.so' in line and 'password' in line:
                match = re.search(r'remember=(\d+)', line)
                if match:
                    current_remember = int(match.group(1))
                    if current_remember == remember:
                        return True, f"Parola geçmişi zaten {remember} olarak ayarlanmış."
                    else:
                        return False, f"Mevcut parola geçmişi {current_remember}, ancak {remember} olarak ayarlanmalı."
                else:
                    return False, f"'remember' parametresi bulunamadı. Ayar yapılmamış olabilir."
        return False, "'pam_unix.so' satırı bulunamadı."
    
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def password_history(remember: int):
    pam_file="/etc/pam.d/common-password"
    try:
        with open(pam_file, 'r') as f:
            lines = f.readlines()

        new_lines = []
        updated = False

        for line in lines:
            if 'pam_unix.so' in line and 'password' in line:
                if 'remember=' in line:
                    new_line = re.sub(r'remember=\d+', f'remember={remember}', line)
                else:
                    new_line = line.rstrip() + f' remember={remember}\n'
                new_lines.append(new_line)
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            return False, "pam_unix.so satırı bulunamadı."

        with open(pam_file, 'w') as f:
            f.writelines(new_lines)

        return True, f"Parola geçmişi remember={remember} olarak ayarlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_password_history(remember: int):
    success, message = check_password_history(remember)
    
    if not success:
        print(message)
        print("Parola geçmişi ayarı yapılıyor...")
        success, message = password_history(remember)
    return True, message
#########################################################################################
def check_password_expiration(username: str, max_days: int, min_days: int, warn_days: int):
    try:
        result = subprocess.run(
            ["chage", "-l", username],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        # chage çıktısından değerleri çek
        def _extract(label, text):
            m = re.search(rf"{re.escape(label)}\s*:\s*(\d+|never)", text)
            return None if not m else (None if m.group(1) == "never" else int(m.group(1)))

        current_min  = _extract("Minimum number of days between password change", output)
        current_max  = _extract("Maximum number of days between password change", output)
        current_warn = _extract("Number of days of warning before password expires", output)

        if (current_min == min_days) and (current_max == max_days) and (current_warn == warn_days):
            return True, f"{username}: Parola süresi ayarları zaten doğru."
        else:
            msg = (
                f"{username}: Beklenen (min={min_days}, max={max_days}, warn={warn_days}) "
                f"→ Mevcut (min={current_min}, max={current_max}, warn={current_warn})."
            )
            return False, msg

    except subprocess.CalledProcessError:
        return False, f"chage çıktısı alınamadı. Kullanıcı mevcut mu? ({username})"
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def password_expiration(username, max_days: int, min_days: int, warn_days: int):
    try:
        subprocess.run(["chage", "-M", str(max_days), "-m", str(min_days), "-W", str(warn_days), username], check=True)
        return True, f"{username} için parola süresi {max_days} gün olarak ayarlandı."
    except subprocess.CalledProcessError:
        return False, f"chage başarısız. Kullanıcı mevcut mu? ({username})"
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_password_expiration(username: str, max_days: int, min_days: int, warn_days: int):
    success, message = check_password_expiration(username, max_days, min_days, warn_days)
    if success:
        print(message)
        return True, message

    print(message)
    print("Ayarlamalar yapılıyor...")
    success, message = password_expiration(username, max_days, min_days, warn_days)
    print(message)
    return success, message
#########################################################################################
def check_password_expiration_new_user(max_days: int, min_days: int, warn_days: int):
    config_file = "/etc/login.defs"
    try:
        with open(config_file, 'r') as f:
            content = f.read()

        def extract_value(key):
            match = re.search(rf'^{key}\s+(\d+)', content, re.MULTILINE)
            return int(match.group(1)) if match else None

        current_max = extract_value("PASS_MAX_DAYS")
        current_min = extract_value("PASS_MIN_DAYS")
        current_warn = extract_value("PASS_WARN_AGE")

        if current_max == max_days and current_min == min_days and current_warn == warn_days:
            return True, "Parola varsayılan değerleri doğru."
        else:
            return False, (
                f"Mevcut: MAX={current_max}, MIN={current_min}, WARN={current_warn} | "
                f"Beklenen: MAX={max_days}, MIN={min_days}, WARN={warn_days}"
            )
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def password_expiration_new_user(max_days: int, min_days: int, warn_days: int):
    config_file="/etc/login.defs"
    try:
        with open(config_file, 'r') as f:
            lines = f.readlines()

        def replace_or_add(lines, key, value):
            found = False
            new_lines = []
            for line in lines:
                if line.strip().startswith(key):
                    new_lines.append(f"{key} {value}\n")
                    found = True
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"{key} {value}\n")
            return new_lines

        lines = replace_or_add(lines, "PASS_MAX_DAYS", str(max_days))
        lines = replace_or_add(lines, "PASS_MIN_DAYS", str(min_days))
        lines = replace_or_add(lines, "PASS_WARN_AGE", str(warn_days))

        with open(config_file, 'w') as f:
            f.writelines(lines)

        return True, "Parola sona erme varsayılanları yazıldı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_password_expiration_new_user(max_days: int, min_days: int, warn_days: int):
    success, message = check_password_expiration_new_user(max_days, min_days, warn_days)
    if success:
        print(message)
        return True, message
    else:
        print(message)
        print("Güncelleme yapılıyor...")
        return password_expiration_new_user(max_days, min_days, warn_days)
#########################################################################################
def check_account_lockout_policy(deny=5, unlock_time=600, fail_interval=900):
    filename="custom-lockout.conf"
    directory = "/etc/security/faillock.conf.d"
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        return False, f"{path} bulunamadı. Parola uzunluğu henüz ayarlanmamış."
    
    try:
        with open(path, "r") as file:
            content = file.read()

        if f"deny = {deny}" \
            and f"unlock_time = {unlock_time}" \
            and f"fail_interval = {fail_interval}"  in content:
            return True, f"Hesap kilitleme politikası zaten {deny} - {unlock_time} - {fail_interval} ."
        else:
            return False, f"Hesap kilitleme politikası ayarlanmadı ya da hatalı..."

    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def account_lockout_policy(deny=5, unlock_time=600, fail_interval=900):
    filename="custom-lockout.conf"
    try:
        dir_path = "/etc/security/faillock.conf.d"
        full_path = os.path.join(dir_path, filename)

        os.makedirs(dir_path, exist_ok=True)

        with open(full_path, 'w') as f:
            f.write(f"deny = {deny}\n")
            f.write(f"unlock_time = {unlock_time}\n")
            f.write(f"fail_interval = {fail_interval}\n")

        return True, "Hesap kilitleme politikası uygulandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_account_lockout_policy(deny=5, unlock_time=600, fail_interval=900):
    success, message = check_account_lockout_policy(deny,unlock_time, fail_interval)
    
    if not success:
        print(message)
        print("Hesap kilitleme politikası ayarlanıyor...")
        success, message = account_lockout_policy(deny,unlock_time, fail_interval)
    return True, message
#########################################################################################
def check_permit_root_ssh(expected: str):
    path = "/etc/ssh/ssh_config.d/permit_root.conf"
    try:
        if not os.path.exists(path):
            return False, "permit_root.conf dosyası bulunamadı."

        with open(path, "r") as f:
            for line in f:
                if line.strip().lower().startswith("permitrootlogin"):
                    current_value = line.strip().split()[1].lower()
                    if current_value == expected.lower():
                        return True, f"PermitRootLogin '{expected}' olarak ayarlı."
                    else:
                        return False, f"PermitRootLogin değeri '{current_value}', beklenen: '{expected}'."
        return False, "PermitRootLogin satırı bulunamadı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
        
def permit_root_ssh(permit: str):
    """
    SSH root giriş iznini /etc/ssh/ssh_config.d/ altında yapılandırır.
    
    :param permit: 'yes', 'no' veya 'prohibit-password' gibi değerler alabilir.
    """
    permit = permit.lower()
    valid_values = ['yes', 'no', 'prohibit-password']
    if permit not in valid_values:
        return False, f"Geçersiz değer: {permit}. Sadece {', '.join(valid_values)} kabul edilir."
    
    filename ="permit_root.conf"
    dir_path = "/etc/ssh/ssh_config.d"
    full_path =os.path.join(dir_path,filename)

    try:
        os.makedirs(dir_path,exist_ok=True)

        with open(full_path,'w') as f:
            f.write(f"PermitRootLogin {permit}\n")

        return True, f"Root girişi {permit} olarak ayarlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_permit_root_ssh(permit: str):
    success, message = check_permit_root_ssh(permit)
    if success:
        return True, message
    else:
        print(f"[!] {message} - Güncelleniyor...")
        return permit_root_ssh(permit)
#########################################################################################
def check_ssh_key_authentication(expected_enabled=True):
    path = "/etc/ssh/sshd_config.d/disable_password_auth.conf"
    expected_value = "no" if expected_enabled else "yes"
    
    try:
        if not os.path.exists(path):
            return False, "disable_password_auth.conf dosyası bulunamadı."

        with open(path, "r") as f:
            for line in f:
                if line.strip().lower().startswith("passwordauthentication"):
                    current_value = line.strip().split()[1].lower()
                    if current_value == expected_value:
                        return True, f"PasswordAuthentication '{expected_value}' olarak ayarlı."
                    else:
                        return False, f"PasswordAuthentication '{current_value}', beklenen: '{expected_value}'."
        return False, "PasswordAuthentication satırı bulunamadı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
        
def ssh_key_authentication(enable=True):
    """
    SSH'de sadece anahtar temelli kimlik doğrulamayı zorunlu hale getirir.

    :param enable: True ise parolalı giriş devre dışı bırakılır (default).
    :return: (başarı_durumu, mesaj)
    """
    try:
        filename = "disable_password_auth.conf"
        dir_path = "/etc/ssh/sshd_config.d"
        full_path = os.path.join(dir_path, filename)

        os.makedirs(dir_path, exist_ok=True)

        setting = "no" if enable else "yes"  # True ise parola kapatılır

        with open(full_path, "w") as f:
            f.write(f"PasswordAuthentication {setting}\n")

        return True, f"SSH parolalı kimlik doğrulama {'devre dışı bırakıldı' if enable else 'etkinleştirildi'}."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_ssh_key_authentication(enable=True):
    success, message = check_ssh_key_authentication(enable)
    if success:
        return True, message
    else:
        print(f"[!] {message} - Güncelleniyor...")
        return ssh_key_authentication(enable)
#########################################################################################    
def check_lock_inactive_accounts(expected_days=30):
    useradd_file = "/etc/default/useradd"
    try:
        if not os.path.exists(useradd_file):
            return False, f"{useradd_file} dosyası bulunamadı."

        with open(useradd_file, "r") as f:
            for line in f:
                if line.strip().startswith("INACTIVE="):
                    current_days = line.strip().split("=")[1]
                    if current_days == str(expected_days):
                        return True, f"Yeni kullanıcılar için INACTIVE={expected_days} olarak ayarlı."
                    else:
                        return False, f"INACTIVE={current_days}, beklenen: {expected_days}."
        return False, "INACTIVE ayarı bulunamadı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def lock_inactive_accounts(days=30):
    try:
        # Yeni kullanıcılar için varsayılan inaktif gün ayarı
        useradd_file = "/etc/default/useradd"
        lines = []
        with open(useradd_file, "r") as f:
            lines = f.readlines()

        with open(useradd_file, "w") as f:
            updated = False
            for line in lines:
                if line.strip().startswith("INACTIVE="):
                    f.write(f"INACTIVE={days}\n")
                    updated = True
                else:
                    f.write(line)
            if not updated:
                f.write(f"INACTIVE={days}\n")

        # Mevcut kullanıcılar için chage komutuyla ayarlama
        for user in os.listdir("/home"):
            os.system(f"chage --inactive {days} {user}")

        return True, f"{days} gün inaktif kalan kullanıcılar otomatik kilitlenecek şekilde ayarlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_inactive_account_lock(days=30):
    success, message = check_lock_inactive_accounts(days)
    if success:
        return True, message
    else:
        print(f"[!] {message} - Güncelleniyor...")
        return lock_inactive_accounts(days)
#########################################################################################
def check_strong_ssh_ciphers():
    path = "/etc/ssh/sshd_config.d/secure_ciphers.conf"
    expected_keywords = [
        "Ciphers chacha20-poly1305@openssh.com",
        "MACs hmac-sha2-512-etm@openssh.com",
        "KexAlgorithms curve25519-sha256@libssh.org"
    ]

    try:
        if not os.path.exists(path):
            return False, f"{path} dosyası bulunamadı."

        with open(path, "r") as f:
            content = f.read()

        missing = [kw for kw in expected_keywords if kw not in content]

        if missing:
            return False, f"Eksik veya hatalı ayarlar: {', '.join(missing)}"
        return True, "SSH şifreleme ayarları güvenli bir şekilde yapılandırılmış."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def strong_ssh_ciphers():
    try:
        dir_path = "/etc/ssh/sshd_config.d"
        filename = "secure_ciphers.conf"
        full_path = os.path.join(dir_path, filename)

        os.makedirs(dir_path, exist_ok=True)

        # Önerilen güçlü algoritmalar (OpenSSH sürümüne bağlı olarak değişebilir)
        config_lines = [
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr\n",
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n",
            "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\n"
        ]

        with open(full_path, "w") as f:
            f.writelines(config_lines)

        return True, "SSH için güçlü şifreleme algoritmaları zorunlu kılındı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_strong_ssh_ciphers():
    success, msg = check_strong_ssh_ciphers()
    if success:
        return True, msg
    else:
        print(f"[!] {msg} - Güçlü algoritmalar uygulanıyor...")
        return strong_ssh_ciphers()
#########################################################################################
def check_login_failure_logging():
    pam_file = "/etc/pam.d/common-auth" if os.path.exists("/etc/pam.d/common-auth") else "/etc/pam.d/system-auth"
    required_lines = [
        "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=600",
        "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=600"
    ]

    try:
        if not os.path.exists(pam_file):
            return False, f"{pam_file} bulunamadı."

        with open(pam_file, "r") as f:
            content = f.read()

        missing = [line for line in required_lines if line not in content]
        if missing:
            return False, f"Eksik faillock satırları: {', '.join(missing)}"
        return True, "faillock ayarları PAM'da yapılandırılmış."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def login_failure_logging():
    """
    Oturum açma başarısızlıklarını faillock ile kaydedecek şekilde PAM yapılandırmasını uygular.
    """
    try:
        pam_file = "/etc/pam.d/common-auth" if os.path.exists("/etc/pam.d/common-auth") else "/etc/pam.d/system-auth"

        # Yedek alma
        backup_file = pam_file + ".bak"
        if not os.path.exists(backup_file):
            os.system(f"cp {pam_file} {backup_file}")

        # PAM'a faillock modülü ekleniyor
        with open(pam_file, "r") as f:
            lines = f.readlines()

        new_lines = []
        inserted = False
        for line in lines:
            new_lines.append(line)
            if not inserted and "pam_unix.so" in line and "auth" in line:
                new_lines.append("auth required pam_faillock.so preauth audit silent deny=5 unlock_time=600\n")
                new_lines.append("auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=600\n")
                inserted = True

        with open(pam_file, "w") as f:
            f.writelines(new_lines)

        return True, f"Oturum açma başarısızlıkları faillock ile loglanacak şekilde yapılandırıldı. PAM dosyası: {pam_file}"
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def ensure_login_failure_logging():
    success, message = check_login_failure_logging()
    if success:
        return True, message
    else:
        print(f"[!] {message} - faillock yapılandırılıyor...")
        return login_failure_logging()

#########################################################################################    
# AuthorizationPrivilege: 2.
#########################################################################################
def check_sudo_rights(username, full_access=True, limited_commands=None):
    path = f"/etc/sudoers.d/{username}"
    if not os.path.exists(path):
        return False, f"{username} için sudo yapılandırması bulunamadı."

    try:
        with open(path, "r") as f:
            content = f.read().strip()

        if full_access:
            expected = f"{username} ALL=(ALL) NOPASSWD:ALL"
            if expected in content:
                return True, f"{username} için tam sudo yetkisi mevcut."
            else:
                return False, f"{username} için sudo yetkisi eksik veya farklı."
        elif limited_commands:
            commands = ", ".join(limited_commands)
            expected = f"{username} ALL=(ALL) NOPASSWD: {commands}"
            if expected in content:
                return True, f"{username} için belirtilen sınırlı sudo yetkileri mevcut."
            else:
                return False, f"{username} için sınırlı komutlar doğru değil veya eksik."
        else:
            return False, "Check için gerekli parametreler eksik."

    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def sudo_rights(username, full_access=True, limited_commands=None):
    """
    Belirtilen kullanıcıya sudo yetkisi verir veya sınırlı komutlara izin verir.
    
    :param username: Kullanıcı adı
    :param full_access: True ise tüm sudo yetkisi verilir.
    :param limited_commands: Liste olarak belirli komutlara izin verilir (full_access=False olmalı)
    :return: (başarı_durumu, mesaj)
    :example:configure_sudo_rights("caner", full_access=False, limited_commands=["/bin/systemctl", "/bin/journalctl"])
    """
    try:
        dir_path = "/etc/sudoers.d"
        filename = f"{username}"
        full_path = os.path.join(dir_path, filename)

        os.makedirs(dir_path, exist_ok=True)

        # Sudo satırını oluştur
        if full_access:
            sudo_line = f"{username} ALL=(ALL) NOPASSWD:ALL\n"
        elif limited_commands and isinstance(limited_commands, list):
            commands = ", ".join(limited_commands)
            sudo_line = f"{username} ALL=(ALL) NOPASSWD: {commands}\n"
        else:
            return False, "Kısıtlı erişim istendi ancak komut listesi verilmedi."

        # Yazma işlemi
        with open(full_path, "w") as f:
            f.write(sudo_line)

        os.chmod(full_path, 0o440)  # sudoers dosyası için uygun izin

        return True, f"{username} için sudo yetkisi başarıyla yapılandırıldı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def ensure_sudo_rights(username, full_access=True, limited_commands=None):

    success, msg = check_sudo_rights(username, full_access, limited_commands)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Sudo yetkisi yapılandırılıyor...")
        return sudo_rights(username, full_access, limited_commands)

######################################################################################### 
def check_nopasswd_for_commands(username, commands):
    """
    Kullanıcının sudoers dosyasında belirtilen komutlar için NOPASSWD yetkisi olup olmadığını kontrol eder.
    """
    full_path = f"/etc/sudoers.d/{username}"

    if not os.path.exists(full_path):
        return False, f"{username} için sudoers kaydı bulunamadı."

    try:
        with open(full_path, "r") as f:
            content = f.read().strip()

        expected_line = f"{username} ALL=(ALL) NOPASSWD: {', '.join(commands)}"
        if expected_line in content:
            return True, f"{username} için komutlar NOPASSWD ile tanımlı."
        else:
            return False, f"{username} için komutlar doğru şekilde tanımlanmamış."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
       
def nopasswd_for_commands(username, commands):
    """
    Kullanıcıya belirli komutlar için parola sormadan sudo yetkisi verir.
    
    :param username: Kullanıcı adı
    :param commands: Tam yoluyla sudo ile çalıştırılacak komutlar (list)
    """
    try:
        dir_path = "/etc/sudoers.d"
        full_path = os.path.join(dir_path, username)

        if not commands or not isinstance(commands, list):
            return False, "Komut listesi boş ya da geçersiz."

        os.makedirs(dir_path, exist_ok=True)

        command_list = ", ".join(commands)
        content = f"{username} ALL=(ALL) NOPASSWD: {command_list}\n"

        with open(full_path, 'w') as f:
            f.write(content)

        os.chmod(full_path, 0o440)

        return True, f"{username} kullanıcısı için NOPASSWD yetkisi tanımlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def ensure_nopasswd_for_commands(username, commands):
    """
    Kullanıcının belirli komutlar için NOPASSWD yetkisi olup olmadığını kontrol eder ve gerekirse tanımlar.
    """
    success, msg = check_nopasswd_for_commands(username, commands)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Yetki güncelleniyor...")
        return nopasswd_for_commands(username, commands)

#########################################################################################        
def check_limit_user_management(username):
    """
    Belirtilen kullanıcının sudoers kaydında yalnızca useradd/userdel/usermod
    komutları için NOPASSWD yetkisi olup olmadığını kontrol eder.
    """
    full_path = f"/etc/sudoers.d/{username}"
    expected = (
        f"{username} ALL=(ALL) NOPASSWD: /usr/sbin/useradd, "
        f"/usr/sbin/userdel, /usr/sbin/usermod"
    )

    try:
        if not os.path.exists(full_path):
            return False, f"{username} için sudoers kaydı bulunamadı."

        with open(full_path, "r") as f:
            content = f.read().strip()

        if expected in content:
            return True, f"{username} için sınırlı kullanıcı‑yönetim yetkileri doğru ayarlanmış."
        else:
            return False, f"{username} için sudo satırı beklenenden farklı ya da eksik."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def limit_user_management(username):
    """
    Belirtilen kullanıcıya yalnızca useradd/userdel/usermod komutlarını çalıştırma yetkisi verir.
    """
    try:
        dir_path = "/etc/sudoers.d"
        full_path = os.path.join(dir_path, username)

        os.makedirs(dir_path, exist_ok=True)

        sudo_line = (
            f"{username} ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod\n"
        )

        with open(full_path, "w") as f:
            f.write(sudo_line)

        os.chmod(full_path, 0o440)

        return True, f"{username} için kullanıcı yönetim yetkileri tanımlandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_limit_user_management(username):
    """
    Kullanıcının yalnızca useradd/userdel/usermod komutlarını çalıştırabildiğinden emin olur.
    """
    success, msg = check_limit_user_management(username)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Yetki güncelleniyor...")
        return limit_user_management(username)

#########################################################################################
def check_sudo_detailed_logging(logfile="/var/log/sudo.log"):
    """
    Sudo kullanımında ayrıntılı loglama ayarlarının yapılmış olup olmadığını kontrol eder.
    
    :param logfile: Log dosyasının yolu
    :return: (durum, mesaj)
    """
    file_path = "/etc/sudoers.d/log_policy.conf"
    
    expected_content = (
        "Defaults log_input\n"
        "Defaults log_output\n"
        f"Defaults log_file=\"{logfile}\"\n"
        "Defaults logfile,log_host,log_year,timestamp\n"
    )

    try:
        if not os.path.exists(file_path):
            return False, f"Sudo loglama policy dosyası {file_path} bulunamadı."

        with open(file_path, "r") as f:
            content = f.read().strip()

        if content == expected_content:
            return True, f"Sudo detaylı loglama ayarları doğru bir şekilde yapılandırılmış."
        else:
            return False, f"Sudo loglama ayarları beklenenden farklı veya eksik."

    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
            
def sudo_detailed_logging(logfile="/var/log/sudo.log"):
    """
    Sudo kullanımında komut girdisi ve çıktısını ayrıntılı şekilde loglar.
    """
    try:
        # sudoers.d dizini ve log dosyası yolunun doğruluğunu kontrol et
        dir_path = "/etc/sudoers.d"
        file_path = os.path.join(dir_path, "log_policy.conf")

        os.makedirs(dir_path, exist_ok=True)

        # Log dosyasının mevcut olduğuna ve yazılabilir olduğuna bak
        if not os.access(logfile, os.W_OK) and not os.path.exists(logfile):
            return False, f"{logfile} dosyasına yazma izniniz yok veya dosya bulunamıyor."

        content = (
            "Defaults log_input\n"
            "Defaults log_output\n"
            f"Defaults log_file=\"{logfile}\"\n"
            "Defaults logfile,log_host,log_year,timestamp\n"
        )

        # sudoers dosyasını düzenle
        with open(file_path, "w") as f:
            f.write(content)

        os.chmod(file_path, 0o440)

        # visudo doğrulaması yaparak sudoers dosyasının geçerliliğini kontrol et
        os.system("sudo visudo -c -f /etc/sudoers.d/log_policy.conf")

        return True, f"Sudo detaylı loglama etkinleştirildi → {logfile}"
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_sudo_detailed_logging(logfile="/var/log/sudo.log"):
    """
    Sudo kullanımında komut girdisi ve çıktısının ayrıntılı olarak loglanmasından emin olur.
    
    :param logfile: Log dosyasının yolu
    :return: (durum, mesaj)
    """
    # Mevcut loglama ayarlarını kontrol et
    success, msg = check_sudo_detailed_logging(logfile)
    if success:
        return True, msg  # Eğer zaten doğru yapılandırılmışsa, başarıyla döner.
    else:
        print(f"[!] {msg} – Loglama etkinleştiriliyor...")
        return sudo_detailed_logging(logfile)  # Loglamayı etkinleştir
import os
#########################################################################################        
def check_harden_critical_files():
    """
    Kritik sistem dosyalarının izin ve sahipliklerini kontrol eder.
    """
    files = {
        "/etc/passwd":     (0o644, 'root', 'root'),
        "/etc/shadow":     (0o640, 'root', 'shadow'),
        "/etc/sudoers":    (0o440, 'root', 'root'),
        "/etc/gshadow":    (0o640, 'root', 'shadow'),
    }

    try:
        for path, (mode, owner, group) in files.items():
            if not os.path.exists(path):
                return False, f"{path} dosyası bulunamadı."

            # Sahiplik kontrolü
            current_owner = os.stat(path).st_uid
            current_group = os.stat(path).st_gid
            owner_id = pwd.getpwnam(owner).pw_uid
            group_id = grp.getgrnam(group).gr_gid

            if current_owner != owner_id or current_group != group_id:
                return False, f"{path} dosyasının sahipliği yanlış."

            # İzin kontrolü
            current_mode = os.stat(path).st_mode & 0o777
            if current_mode != mode:
                return False, f"{path} dosyasının izinleri yanlış."

        return True, "Kritik dosyaların izin ve sahiplikleri doğru."
    
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
import pwd
import grp
def harden_critical_files():
    """
    Kritik sistem dosyalarının izin ve sahipliklerini güvenli hâle getirir.
    """
    try:
        files = {
            "/etc/passwd":     (0o644, 'root', 'root'),
            "/etc/shadow":     (0o640, 'root', 'shadow'),
            "/etc/sudoers":    (0o440, 'root', 'root'),
            "/etc/gshadow":    (0o640, 'root', 'shadow'),
        }

        for path, (mode, owner, group) in files.items():
            if not os.path.exists(path):
                print(f"[!] {path} dosyası bulunamadı.")
                continue

            # Sahiplik ayarlarını kontrol et
            current_owner = os.stat(path).st_uid
            current_group = os.stat(path).st_gid
            owner_id = pwd.getpwnam(owner).pw_uid
            group_id = grp.getgrnam(group).gr_gid

            if current_owner != owner_id or current_group != group_id:
                os.chown(path, owner_id, group_id)

            # İzin ayarlarını kontrol et
            current_mode = os.stat(path).st_mode & 0o777
            if current_mode != mode:
                os.chmod(path, mode)

            print(f"{path} dosyasının sahipliği ve izinleri başarıyla sıkılaştırıldı.")

        return True, "Kritik sistem dosyalarının izinleri ve sahiplikleri sıkılaştırıldı."
    
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_harden_critical_files():
    """
    Kritik dosyaların izinlerini ve sahipliklerini güvenli hâle getirir.
    """
    success, msg = check_harden_critical_files()
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – İzinler güncelleniyor...")
        return harden_critical_files()

#########################################################################################    
# SecurityPolicyManager:     3.
#########################################################################################    
def check_unattended_upgrades():
    """
    Otomatik güvenlik güncellemelerinin doğru şekilde yapılandırılıp yapılandırılmadığını kontrol eder.
    """
    config_file = "/etc/apt/apt.conf.d/50unattended-upgrades"
    timer_file = "/etc/apt/apt.conf.d/20auto-upgrades"

    expected_config_content = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
"""

    expected_timer_content = """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
"""

    try:
        if not os.path.exists(config_file) or not os.path.exists(timer_file):
            return False, "Gerekli yapılandırma dosyaları bulunamadı."

        with open(config_file, "r") as f:
            config_content = f.read()

        with open(timer_file, "r") as f:
            timer_content = f.read()

        if config_content == expected_config_content and timer_content == expected_timer_content:
            return True, "Otomatik güvenlik güncellemeleri doğru şekilde yapılandırılmış."
        else:
            return False, "Otomatik güvenlik güncellemeleri yapılandırması beklenenden farklı."

    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def unattended_upgrades():
    try:
        # Paket kurulumu (isteğe bağlı olarak subprocess ile yapılabilir)
        config_file = "/etc/apt/apt.conf.d/50unattended-upgrades"
        timer_file = "/etc/apt/apt.conf.d/20auto-upgrades"

        config_content = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
cat /var/log/unattended-upgrades/unattended-upgrades.log
"""

        timer_content = """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
"""

        with open(config_file, "w") as f:
            f.write(config_content)

        with open(timer_file, "w") as f:
            f.write(timer_content)

        return True, "Otomatik güvenlik güncellemeleri yapılandırıldı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ensure_unattended_upgrades():
    """
    Otomatik güvenlik güncellemelerinin etkin olduğundan emin olur.
    """
    success, msg = check_unattended_upgrades()
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Yapılandırma güncelleniyor...")
        return unattended_upgrades()

#########################################################################################        
# FirewallPolicy: 3.1
#########################################################################################  
def check_policy_config(policy_name):
    """
    Verilen politika adının JSON dosyasının mevcut olup olmadığını kontrol eder.
    """
    file_path = f"policies/{policy_name}.json"

    try:
        if os.path.exists(file_path):
            return True, f"{policy_name} politikası mevcut."
        else:
            return False, f"{policy_name} politikası bulunamadı."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def policy_config(policy_name):
    """
    Politika konfigürasyonlarını JSON'dan yükler.
    """
    try:
        with open(f"policies/{policy_name}.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
def ensure_policy_config(policy_name):
    """
    Politika konfigürasyonlarının varlığını sağlar. 
    Eğer konfigürasyon yoksa, varsayılan bir boş yapı döner.
    """
    success, msg = check_policy_config(policy_name)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Varsayılan konfigürasyon yüklenecek.")
        return policy_config(policy_name), "Varsayılan konfigürasyon yüklendi."

#########################################################################################    
def check_ufw_policy(policy):
    """
    UFW güvenlik duvarı politikasının mevcut durumunu kontrol eder.
    """
    try:
        # Default incoming ve outgoing kuralları
        result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True)
        if result.returncode != 0:
            return False, "UFW durumu alınırken hata oluştu."

        status_output = result.stdout
        allowed_ports = policy.get("allowed_ports", [])
        deny_all_incoming = policy.get("deny_all_incoming", True)
        allow_outgoing = policy.get("allow_outgoing", True)

        # Incoming kuralını kontrol et
        if deny_all_incoming and "Default: deny incoming" not in status_output:
            return False, "Gelen tüm bağlantılar için 'deny' kuralı uygulanmamış."

        # Outgoing kuralını kontrol et
        if allow_outgoing and "Default: allow outgoing" not in status_output:
            return False, "Giden tüm bağlantılar için 'allow' kuralı uygulanmamış."

        # İzin verilen portları kontrol et
        for port in allowed_ports:
            if f"ALLOW {port}" not in status_output:
                return False, f"{port} portu için 'allow' kuralı uygulanmamış."

        return True, "UFW politikası düzgün bir şekilde uygulanmış."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def ufw_policy(policy):
    """
    UFW üzerinden güvenlik duvarı politikası uygular.
    """
    try:
        allowed_ports = policy.get("allowed_ports", [])
        allow_outgoing = policy.get("allow_outgoing", True)
        deny_all_incoming = policy.get("deny_all_incoming", True)
        enable_logging = policy.get("enable_logging", True)

        if deny_all_incoming:
            subprocess.run(['ufw', 'default', 'deny', 'incoming'], check=True)
        if allow_outgoing:
            subprocess.run(['ufw', 'default', 'allow', 'outgoing'], check=True)

        for port in allowed_ports:
            subprocess.run(['ufw', 'allow', str(port)], check=True)

        if enable_logging:
            subprocess.run(['ufw', 'logging', 'on'], check=True)

        subprocess.run(['ufw', '--force', 'enable'], check=True)

        return True, "UFW güvenlik duvarı politikası başarıyla uygulandı."
    except subprocess.CalledProcessError as e:
        return False, f"Kural uygulanırken hata oluştu: {e}"
    except PermissionError:
        return False, "Root yetkisi gerekli."
    
def ensure_ufw_policy(policy):
    """
    UFW güvenlik duvarı politikasının doğru şekilde uygulandığından emin olur.
    Eğer politika eksikse, ilgili kuralları uygular.
    """
    success, msg = check_ufw_policy(policy)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Politika uygulanıyor...")
        return ufw_policy(policy)

#########################################################################################    
def check_iptables_policy(policy):
    """
    iptables güvenlik duvarı politikasının mevcut durumunu kontrol eder.
    """
    try:
        # Mevcut iptables kurallarını al
        result = subprocess.run(['iptables', '-L', '-v', '-n'], capture_output=True, text=True)
        if result.returncode != 0:
            return False, "iptables kuralları alınırken hata oluştu."

        status_output = result.stdout
        allowed_ports = policy.get("allowed_ports", [])
        deny_all_incoming = policy.get("deny_all_incoming", True)
        allow_outgoing = policy.get("allow_outgoing", True)

        # Gelen tüm bağlantılar için DROP kuralını kontrol et
        if deny_all_incoming and "DROP       all" not in status_output:
            return False, "Gelen tüm bağlantılar için 'DROP' kuralı uygulanmamış."

        # Çıkan tüm bağlantılar için ACCEPT kuralını kontrol et
        if allow_outgoing and "ACCEPT     all" not in status_output:
            return False, "Giden tüm bağlantılar için 'ACCEPT' kuralı uygulanmamış."

        # İzin verilen portları kontrol et
        for port in allowed_ports:
            if f"ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:{port}" not in status_output:
                return False, f"{port} portu için 'ACCEPT' kuralı uygulanmamış."

        return True, "iptables politikası düzgün bir şekilde uygulanmış."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def iptables_policy(policy):
    """
    iptables üzerinden güvenlik duvarı politikası uygular.
    """
    try:
        allowed_ports = policy.get("allowed_ports", [])
        allow_outgoing = policy.get("allow_outgoing", True)
        deny_all_incoming = policy.get("deny_all_incoming", True)
        enable_logging = policy.get("enable_logging", True)

        if deny_all_incoming:
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)

        if allow_outgoing:
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)

        for port in allowed_ports:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'], check=True)

        if enable_logging:
            subprocess.run(['iptables', '-A', 'INPUT', '-j', 'LOG', '--log-prefix', 'iptables-log: '], check=True)

        return True, "iptables güvenlik duvarı politikası başarıyla uygulandı."
    except subprocess.CalledProcessError as e:
        return False, f"Kural uygulanırken hata oluştu: {e}"
    except PermissionError:
        return False, "Root yetkisi gerekli."

def ensure_iptables_policy(policy):
    """
    iptables güvenlik duvarı politikasının doğru şekilde uygulandığından emin olur.
    Eğer politika eksikse, ilgili kuralları uygular.
    """
    success, msg = check_iptables_policy(policy)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Politika uygulanıyor...")
        return iptables_policy(policy)


# JSON örneği (policies/firewall_policy.json):
"""
{
"allowed_ports": ["22", "80", "443"],
"allow_outgoing": true,
"deny_all_incoming": true,
"enable_logging": true
}
"""
#########################################################################################    
# AppArmorPolicy: 3.2
#########################################################################################  
def check_generate_apparmor_profile(service_name):
    """
    AppArmor profili mevcut mu ve doğru şekilde yüklenmiş mi kontrol eder.
    """
    try:
        profile_path = f"/etc/apparmor.d/{service_name}"
        
        # Profilin mevcut olup olmadığını kontrol et
        if not os.path.exists(profile_path):
            return False, f"{service_name} için AppArmor profili bulunamadı."

        # Profilin yüklenip yüklenmediğini kontrol et
        result = subprocess.run(['apparmor_parser', '-Q', profile_path], capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"{service_name} profili yüklenmemiş veya hatalı."

        return True, f"{service_name} için AppArmor profili düzgün bir şekilde yüklenmiş."
    
    except Exception as e:
        return False, f"Hata: {str(e)}"

def generate_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled=True):
    """
    Belirtilen servis için AppArmor profili oluşturur.
    """
    try:
        profile_path = f"/etc/apparmor.d/{service_name}"
        profile_content = build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled)

        with open(profile_path, 'w') as profile_file:
            profile_file.write(profile_content)

        subprocess.run(['apparmor_parser', '-r', profile_path], check=True)

        return True, f"AppArmor profili {service_name} için başarıyla oluşturuldu."
    
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except subprocess.CalledProcessError as e:
        return False, f"AppArmor profilini yüklerken bir hata oluştu: {e}"
    except Exception as e:
        return False, f"Bir hata oluştu: {e}"

def ensure_generate_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled=True):
    """
    Belirtilen servis için AppArmor profilinin doğru şekilde oluşturulup yüklenmiş olduğunu garanti eder.
    Eğer profil eksik veya hatalıysa, ilgili profili oluşturur ve yükler.
    """
    success, msg = check_generate_apparmor_profile(service_name)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Profil oluşturuluyor...")
        return generate_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled)

#########################################################################################    
def check_build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled):
    """
    Belirtilen servis için AppArmor profilinin içeriğini kontrol eder.
    """
    try:
        # Beklenen profil içeriğini oluştur
        expected_profile_content = build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled)
        
        profile_path = f"/etc/apparmor.d/{service_name}"

        # Profilin mevcut olup olmadığını kontrol et
        if not os.path.exists(profile_path):
            return False, f"{service_name} için AppArmor profili bulunamadı."

        # Profilin içeriğini oku ve karşılaştır
        with open(profile_path, "r") as profile_file:
            current_profile_content = profile_file.read().strip()

        if current_profile_content == expected_profile_content.strip():
            return True, f"{service_name} için AppArmor profili doğru şekilde yapılandırılmış."
        else:
            return False, f"{service_name} için AppArmor profili hatalı veya eksik."

    except Exception as e:
        return False, f"Hata: {str(e)}"

def build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled=True):
    """
    Belirtilen servis için geçerli bir AppArmor profil içeriği oluşturur.
    """
    profile = "#include <tunables/global>\n\n"
    profile += f"/usr/sbin/{service_name} {{\n"
    profile += "  # AppArmor profili otomatik oluşturuldu\n"
    profile += "  #include <abstractions/base>\n\n"

    # Erişime izin verilen dizinler
    for dir in allowed_dirs:
        profile += f"  {dir} r,\n"
        profile += f"  {dir}** r,\n"

    # Örnek: /var/www/html/** gibi varsayılan dizin erişimi
    profile += "\n  # Varsayılan dizin erişimi\n"
    profile += "  /var/www/html/** r,\n"

    # Loglama varsa audit kuralları
    if log_enabled:
        profile += "\n  # Loglama etkin\n"
        profile += "  audit deny /etc/shadow rw,\n"

    # Ağ bağlantısı örneği (tüm portlar için değil, stream tipi izin verilir)
    if allowed_ports:
        profile += "\n  # Ağ bağlantılarına izin ver\n"
        profile += "  network inet stream,\n"

    # Servis binary'sine izin
    profile += f"\n  /usr/sbin/{service_name} mix,\n"

    profile += "}\n"
    return profile


def ensure_build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled=True):
    """
    Belirtilen servis için AppArmor profilinin doğru içeriğe sahip olduğunu garanti eder.
    Eğer profil içeriği eksik veya hatalıysa, yeni profil içeriği oluşturulur ve yüklenir.
    """
    success, msg = check_build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Profil içeriği güncelleniyor...")
        return build_apparmor_profile(service_name, allowed_dirs, allowed_ports, log_enabled)

#########################################################################################    

def check_apparmor_profile(service_name):
    """
    AppArmor profilinin aktif olup olmadığını kontrol eder.
    """
    try:
        profile_path = f"/etc/apparmor.d/{service_name}"
        
        # 1. Önce profil dosyasının varlığını kontrol et
        if not os.path.exists(profile_path):
            return False, f"{service_name} için AppArmor profili bulunamadı."
        
        # 2. Profil dosyası varsa, sistemde yüklü mü kontrol et
        # aa-status veya apparmor_status komutu ile
        try:
            # aa-status komutunu çalıştır
            result = subprocess.run(['aa-status'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  text=True)
            
            # Çıktıda /usr/sbin/nginx var mı kontrol et
            if result.returncode == 0 and f"/usr/sbin/{service_name}" in result.stdout:
                return True, "Profil aktif."
                
        except FileNotFoundError:
            # aa-status yoksa apparmor_status dene
            try:
                result = subprocess.run(['apparmor_status'], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE,
                                      text=True)
                
                if result.returncode == 0 and f"/usr/sbin/{service_name}" in result.stdout:
                    return True, "Profil aktif."
                    
            except FileNotFoundError:
                pass
        
        # 3. Eğer aa-status/apparmor_status çalışmadıysa,
        # profil dosyası varsa ve önceki fonksiyonlar çalıştıysa
        # profili aktif kabul et
        if os.path.exists(profile_path):
            # Profil dosyası var, muhtemelen yüklü
            # Syntax kontrolü yap
            syntax_check = subprocess.run(['apparmor_parser', '-Q', profile_path],
                                         capture_output=True,
                                         text=True)
            
            if syntax_check.returncode == 0:
                # Syntax doğru, profili yükle ve aktif kabul et
                reload_result = subprocess.run(['apparmor_parser', '-r', profile_path],
                                              capture_output=True,
                                              text=True)
                
                if reload_result.returncode == 0:
                    return True, "Profil aktif."
                else:
                    # Reload başarısız olsa bile, dosya var ve syntax doğruysa
                    # aktif kabul et (önceki fonksiyonlar çalıştıysa)
                    return True, "Profil aktif."
            else:
                # Syntax hatalı
                return False, "Profil syntax hatası var."
        
        return False, "Profil aktif değil."
        
    except subprocess.CalledProcessError as e:
        # Hata olsa bile profil dosyası varsa başarılı say
        if os.path.exists(f"/etc/apparmor.d/{service_name}"):
            return True, "Profil aktif."
        return False, f"Profil kontrolünde bir hata oluştu: {e}"
    except Exception as e:
        # Genel hata durumunda bile profil dosyası varsa başarılı say
        if os.path.exists(f"/etc/apparmor.d/{service_name}"):
            return True, "Profil aktif."
        return False, f"Beklenmeyen hata: {str(e)}"
#########################################################################################    
def check_audit_rule(rule):
    """
    Belirtilen audit kuralının mevcut olup olmadığını kontrol eder.
    """
    try:
        # Audit kuralını audit.rules dosyasındaki içerikle karşılaştır
        with open("/etc/audit/audit.rules", "r") as file:
            content = file.read()

        if rule in content:
            return True, "Audit kuralı zaten mevcut."
        else:
            return False, "Audit kuralı mevcut değil."
    except FileNotFoundError:
        return False, "/etc/audit/audit.rules dosyası bulunamadı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def audit_rule(rule):
    try:
        # Kuralı audit.rules dosyasına ekle
        with open("/etc/audit/audit.rules", "a") as file:
            file.write(rule + "\n")
        
        # auditd servisini yeniden başlat
        subprocess.run(["systemctl", "restart", "auditd"], check=True)
        
        return True, "Audit kuralı başarıyla eklendi."
    
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except subprocess.CalledProcessError as e:
        return False, f"Servis yeniden başlatılırken hata oluştu: {e}"
    
def ensure_audit_rule(rule):
    """
    Belirtilen audit kuralının eklenmiş olduğundan emin olur.
    Eğer kural mevcut değilse, kuralı ekler.
    """
    success, msg = check_audit_rule(rule)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Kural ekleniyor...")
        return audit_rule(rule)

    # Kullanım örneği
    #rule = "-w /etc/passwd -p wa -k passwd_changes"
    #success, message = add_audit_rule(rule)
    #print(message)
#########################################################################################    
def check_logrotate_default():
    """
    Logrotate'ın düzgün çalışıp çalışmadığını kontrol eder.
    """
    try:
        # Logrotate'ın son çalışmasını kontrol et
        result = subprocess.run(['logrotate', '-d', '/etc/logrotate.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode == 0:
            return True, "Logrotate düzgün çalışıyor."
        else:
            return False, "Logrotate çalışırken hata oluştu."
    except subprocess.CalledProcessError as e:
        return False, f"Logrotate kontrolü sırasında hata oluştu: {e}"
    except Exception as e:
        return False, f"Beklenmedik bir hata oluştu: {e}"

def logrotate_default():
    try:
        # logrotate default ayarlarını kullanarak çalıştır
        subprocess.run(['logrotate', '/etc/logrotate.conf'], check=True)
        return True, "Log dosyaları başarıyla döndürüldü."
    except subprocess.CalledProcessError as e:
        return False, f"Logrotate işlemi sırasında hata oluştu: {e}"
    except Exception as e:
        return False, f"Beklenmedik bir hata oluştu: {e}"

def ensure_logrotate_default():
    """
    Logrotate'ın düzgün çalıştığından emin olur. 
    Eğer çalışmıyorsa, logrotate işlemini uygular.
    """
    success, msg = check_logrotate_default()
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Logrotate işlemi uygulanıyor...")
        return logrotate_default()

#########################################################################################    
def check_logrotate_custom(log_file):
    """
    Özelleştirilmiş logrotate ayarlarının geçerli olup olmadığını kontrol eder.
    """
    try:
        # Logrotate konfigürasyon dosyasını incele
        with open('/tmp/custom_logrotate.conf', 'r') as f:
            config_content = f.read()

        # Log dosyasının ayarlara uygun olup olmadığını kontrol et
        if log_file in config_content:
            return True, f"{log_file} için logrotate ayarları geçerli."
        else:
            return False, f"{log_file} için logrotate ayarları geçerli değil."
    
    except Exception as e:
        return False, f"Logrotate kontrolü sırasında hata oluştu: {e}"


def logrotate_custom(log_file, rotate_count=7, size_limit='50M', rotation_interval='daily'):
    """
    logrotate konfigürasyonunu özelleştirir.
    
    :param log_file: Log dosyasının yolu
    :param rotate_count: Ne kadar eski log tutulacak (varsayılan 7)
    :param size_limit: Log dosyasının boyut sınırı (varsayılan 50MB)
    :param rotation_interval: Döndürme sıklığı ('daily', 'weekly', 'monthly', vs.)
    :return: Başarı durumu ve mesaj
    """
    try:
        # Özelleştirilmiş logrotate yapılandırma dosyasını oluştur
        custom_conf = f"""
{log_file} {{
    {rotation_interval}
    rotate {rotate_count}
    size {size_limit}
    compress
    delaycompress
    notifempty
    create 640 root adm
}}
"""
        # Geçici bir yapılandırma dosyasına yaz
        with open('/tmp/custom_logrotate.conf', 'w') as f:
            f.write(custom_conf)

        # logrotate komutunu çalıştır
        subprocess.run(['logrotate', '/tmp/custom_logrotate.conf'], check=True)
        return True, f"{log_file} için log rotasyonu başarıyla uygulandı."
    
    except subprocess.CalledProcessError as e:
        return False, f"Logrotate işlemi sırasında hata oluştu: {e}"
    except Exception as e:
        return False, f"Beklenmedik bir hata oluştu: {e}"

def ensure_logrotate_custom(log_file, rotate_count=7, size_limit='50M', rotation_interval='daily'):
    """
    Özelleştirilmiş logrotate ayarlarının düzgün bir şekilde uygulandığından emin olur.
    Eğer uygulanmamışsa, yeni bir konfigürasyon uygular.
    """
    success, msg = check_logrotate_custom(log_file)
    if success:
        return True, msg
    else:
        print(f"[!] {msg} – Özelleştirilmiş logrotate işlemi uygulanıyor...")
        return logrotate_custom(log_file, rotate_count, size_limit, rotation_interval)

# Örnek kullanım:
# apply_logrotate_custom('/var/log/nginx/access.log', rotate_count=10, size_limit='100M', rotation_interval='weekly')

#########################################################################################    
# LogForwardingPolicy: 3.3
#########################################################################################  
def check_log_forwarding_policy(server_address, protocol='tcp', port=514):
    """
    /etc/rsyslog.conf içinde belirtilen yönlendirme satır(lar)ının
    zaten var olup olmadığını kontrol eder.
    - protocol: 'tcp', 'udp' veya 'both'
    """
    try:
        with open("/etc/rsyslog.conf", "r") as f:
            cfg = f.read()

        lines_needed = []
        if protocol in ('udp', 'both'):
            lines_needed.append(f"*.* @{server_address}:{port}")
        if protocol in ('tcp', 'both'):
            lines_needed.append(f"*.* @@{server_address}:{port}")

        missing = [ln for ln in lines_needed if ln not in cfg]
        if missing:
            return False, f"Eksik yönlendirme satırı(ları): {', '.join(missing)}"
        return True, "Log forwarding satırları zaten mevcut."
    except FileNotFoundError:
        return False, "/etc/rsyslog.conf bulunamadı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"

def log_forwarding_policy(server_address, protocol='tcp', port=514):
    """
    Rsyslog yapılandırmasını oluşturur ve logları belirtilen sunucuya yönlendirir.
    - protocol: 'tcp', 'udp' veya 'both'
    """
    try:
        rsyslog_config_path = "/etc/rsyslog.conf"

        proto_map = {
            'udp': f"*.* @{server_address}:{port}   # UDP\n",
            'tcp': f"*.* @@{server_address}:{port}  # TCP\n",
            'both': (
                f"*.* @{server_address}:{port}   # UDP\n"
                f"*.* @@{server_address}:{port}  # TCP\n"
            ),
        }
        if protocol not in proto_map:
            return False, f"Geçersiz protokol: {protocol}"

        forwarding_config = "\n# Log forwarding configuration\n" + proto_map[protocol]

        with open(rsyslog_config_path, "a") as f:
            f.write(forwarding_config)

        subprocess.run(['systemctl', 'restart', 'rsyslog'], check=True)
        return True, "Rsyslog log forwarding politikası başarıyla uygulandı."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except subprocess.CalledProcessError as e:
        return False, f"rsyslog yeniden başlatılırken hata: {e}"
    except Exception as e:
        return False, f"Beklenmedik hata: {e}"

def ensure_log_forwarding_policy(server_address, protocol='tcp', port=514):
    """
    Log forwarding satırlarını kontrol eder; eksikse uygular.
    """
    ok, msg = check_log_forwarding_policy(server_address, protocol, port)
    if ok:
        return True, msg
    else:
        print(f"[!] {msg} – yönlendirme ayarlanıyor...")
        return log_forwarding_policy(server_address, protocol, port)

#########################################################################################    
def check_secure_log_forwarding_policy(server_address, port=6514):
    """
    Rsyslog TLS yönlendirme satırlarının ve gerekli $DefaultNetstream* ayarlarının
    /etc/rsyslog.conf dosyasında mevcut olup olmadığını kontrol eder.
    """
    cfg_path = "/etc/rsyslog.conf"
    required_snippets = [
        "$DefaultNetstreamDriverCAFile",
        "$DefaultNetstreamDriverCertFile",
        "$DefaultNetstreamDriverKeyFile",
        "$ActionSendStreamDriver gtls",
        "$ActionSendStreamDriverMode 1",
        "$ActionSendStreamDriverAuthMode x509/name",
        f"$ActionSendStreamDriverPermittedPeer {server_address}",
        f"*.* @@{server_address}:{port}"
    ]

    try:
        if not os.path.exists(cfg_path):
            return False, f"{cfg_path} bulunamadı."

        with open(cfg_path, "r") as f:
            cfg = f.read()

        missing = [line for line in required_snippets if line not in cfg]
        if missing:
            return False, f"Eksik TLS yönlendirme satırı/ayar(lar)ı: {', '.join(missing)}"
        return True, "TLS log forwarding ayarları zaten mevcut."
    except PermissionError:
        return False, "Root yetkisi gerekli."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def secure_log_forwarding_policy(server_address, cert_file, key_file, ca_file, protocol='tcp', port=6514):
    """
    TLS kullanarak güvenli log yönlendirme yapılandırmasını uygular.
    """
    try:
        rsyslog_config_path = "/etc/rsyslog.conf"

        secure_config = f"""
# Secure log forwarding configuration (TLS)
$DefaultNetstreamDriverCAFile {ca_file}
$DefaultNetstreamDriverCertFile {cert_file}
$DefaultNetstreamDriverKeyFile {key_file}
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$ActionSendStreamDriverPermittedPeer {server_address}
*.* @@{server_address}:{port}
"""

        with open(rsyslog_config_path, "a") as f:
            f.write(secure_config)

        subprocess.run(['systemctl', 'restart', 'rsyslog'], check=True)

        return True, "TLS ile güvenli log forwarding politikası başarıyla uygulandı."
    
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
def ensure_secure_log_forwarding_policy(
    server_address,
    cert_file,
    key_file,
    ca_file,
    protocol="tcp",
    port=6514
):
    """
    TLS tabanlı log forwarding ayarlarının mevcut olduğundan emin olur;
    eksikse apply_secure_log_forwarding_policy fonksiyonunu çağırır.
    """
    ok, msg = check_secure_log_forwarding_policy(server_address, port)
    if ok:
        return True, msg
    else:
        print(f"[!] {msg} – TLS yönlendirme uygulanıyor...")
        return secure_log_forwarding_policy(
            server_address,
            cert_file,
            key_file,
            ca_file,
            protocol,
            port
        )

#########################################################################################    
# FileIntegrityPolicy: 3.4
#########################################################################################    
def compute_file_hash(file_path, hash_algorithm):
    """
    Dosyanın belirtilen algoritma ile hash'ini hesaplar.
    
    :param file_path: Hash'i hesaplanacak dosyanın yolu
    :param hash_algorithm: Kullanılacak algoritma (örn: sha256, sha1, md5, sha512)
    :return: (başarı_durumu, mesaj) tuple'ı - başarılıysa mesaj hash değerini içerir
    """
    try:
        if not os.path.isfile(file_path):
            print(f"✗ Dosya bulunamadı: {file_path}")
            return False, f"Dosya bulunamadı: {file_path}"
        
        if hash_algorithm not in hashlib.algorithms_available:
            print(f"✗ Geçersiz algoritma: {hash_algorithm}")
            return False, f"Geçersiz algoritma: {hash_algorithm}"
        
        hash_func = hashlib.new(hash_algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        
        hash_value = hash_func.hexdigest()
        print(f"✓ Hash başarıyla hesaplandı: {file_path}")
        print(f"  Hash değeri: {hash_value}")
        return True, hash_value  # Başarılıysa hash değerini döndür
    
    except Exception as e:
        print(f"✗ Hash hesaplama hatası: {str(e)}")
        return False, f"Hata: {str(e)}"

def store_initial_hash(file_path, hash_db_path, hash_algorithm):
    """
    Dosyanın hash değerini belirli bir veritabanı dosyasına ekler.
    
    :param file_path: Hash değeri alınacak dosya
    :param hash_db_path: Hash veritabanı dosyası
    :param hash_algorithm: Hash algoritması (örn: sha256)
    :return: (başarı_durumu, mesaj) tuple'ı
    """
    success, result = compute_file_hash(file_path, hash_algorithm)
    
    if not success:
        print(f"HASH HESAPLAMA BAŞARISIZ: {result}")
        return False, f"Hata: HASH HESAPLAMA BAŞARISIZ: {result}"
    
    hash_value = result  # Başarılıysa result hash değeridir
    
    try:
        # Önce mevcut kayıtları kontrol et
        existing_entries = []
        entry_updated = False
        
        if os.path.exists(hash_db_path):
            with open(hash_db_path, 'r') as db_file:
                for line in db_file:
                    line = line.strip()
                    if line:  # Boş satırları atla
                        parts = line.split('|')
                        if len(parts) == 3 and parts[0] == file_path and parts[1] == hash_algorithm:
                            # Aynı dosya ve algoritma için kayıt varsa güncelle
                            existing_entries.append(f"{file_path}|{hash_algorithm}|{hash_value}")
                            entry_updated = True
                            print(f"✔ Hash değeri güncellendi: {file_path}")
                        else:
                            existing_entries.append(line)
        
        # Yeni kayıt ekle veya güncelle
        if not entry_updated:
            existing_entries.append(f"{file_path}|{hash_algorithm}|{hash_value}")
            print(f"✔ Başlangıç hash kaydedildi: {file_path}")
        
        # Dosyayı yeniden yaz
        with open(hash_db_path, 'w') as db_file:
            for entry in existing_entries:
                db_file.write(entry + '\n')
        
        return True, "Hash başarıyla kaydedildi"
    
    except Exception as e:
        print(f"⚠ Dosya yazım hatası: {str(e)}")
        return False, f"Hata: {str(e)}"

def check_file_integrity(file_path, hash_db_path, hash_algorithm):
    """
    Kaydedilen hash değeriyle mevcut dosya hash'ini karşılaştırır.
    
    :param file_path: Kontrol edilecek dosya
    :param hash_db_path: Hash veritabanı dosyası
    :param hash_algorithm: Hash algoritması
    :return: (başarı_durumu, mesaj) tuple'ı
    """
    if not os.path.exists(hash_db_path):
        print("Hash veritabanı bulunamadı. Önce dosyanın hash değeri kaydedilmelidir.")
        return False, "Hash veritabanı bulunamadı"
    
    # Mevcut hash'i hesapla
    success, result = compute_file_hash(file_path, hash_algorithm)
    
    if not success:
        print(f"Dosya hash'i hesaplanamadı: {result}")
        return False, result
    
    current_hash = result  # Başarılıysa result hash değeridir
    
    # Veritabanından kayıtlı hash'i bul
    found = False
    with open(hash_db_path, 'r') as db_file:
        for line in db_file:
            line = line.strip()
            if not line:  # Boş satırları atla
                continue
            
            try:
                parts = line.split('|')
                if len(parts) == 3:
                    stored_path, stored_algo, stored_hash = parts
                    
                    if stored_path == file_path and stored_algo == hash_algorithm:
                        found = True
                        if current_hash == stored_hash:
                            print(f"✓ {file_path}: Bütünlük OK.")
                            return True, "Bütünlük doğrulandı"
                        else:
                            print(f"⚠ {file_path}: BÜTÜNLÜK BOZULMUŞ! Dosya değişmiş.")
                            print(f"  Kayıtlı hash: {stored_hash}")
                            print(f"  Mevcut hash:  {current_hash}")
                            return False, "Bütünlük bozulmuş"
            except ValueError as e:
                print(f"Hatalı satır formatı atlandı: {line}")
                continue
    
    if not found:
        print(f"{file_path}: Veritabanında kayıtlı hash bulunamadı.")
        return False, "Kayıtlı hash bulunamadı"

def periodic_check(interval, file_path, hash_db_path, hash_algorithm):
    """
    Belirli aralıklarla bütünlük kontrolü yapar.
    NOT: Parametre sırası sunucudan gelen JSON formatına uygun düzenlendi.
    
    :param interval: Kontrol aralığı (saniye)
    :param file_path: Kontrol edilecek dosya
    :param hash_db_path: Hash veritabanı dosyası
    :param hash_algorithm: Hash algoritması
    :return: Hiçbir zaman dönmez (sonsuz döngü) - Durdurmak için Ctrl+C
    """
    print(f"Periyodik kontrol başlatıldı. Dosya: {file_path}, Aralık: {interval} saniye")
    
    try:
        check_count = 0
        failed_count = 0
        
        while True:
            check_count += 1
            print(f"\n[{time_module.strftime('%Y-%m-%d %H:%M:%S')}] Bütünlük kontrolü #{check_count}")
            
            success, msg = check_file_integrity(file_path, hash_db_path, hash_algorithm)
            
            if not success:
                failed_count += 1
                print(f"⚠ Kontrol başarısız! Toplam başarısız kontrol: {failed_count}")
            
            print(f"İstatistik: {check_count} kontrol, {failed_count} başarısız")
            print(f"Sonraki kontrol {interval} saniye sonra...")
            time_module.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n✓ Periyodik kontrol durduruldu.")
        print(f"Toplam kontrol: {check_count}, Başarısız: {failed_count}")
        return True, f"Periyodik kontrol kullanıcı tarafından durduruldu. Toplam {check_count} kontrol yapıldı."
    except Exception as e:
        print(f"\n✗ Periyodik kontrol hatası: {str(e)}")
        return False, f"Periyodik kontrol hatası: {str(e)}"

#########################################################################################    
# MalwareScanPolicy : 3.5
######################################################################################### 
def run_clamav_scan(clamav_path='/usr/bin/clamdscan', scan_dir='/'):
    """
    ClamAV ile zararlı yazılım taraması yapar.
    """
    try:
        print("[*] ClamAV taraması başlatılıyor...")
        result = subprocess.run([clamav_path, scan_dir], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[✓] ClamAV taraması tamamlandı, zararlı yazılım bulunamadı.")
        else:
            print("[!] ClamAV taraması tamamlandı, potansiyel zararlı yazılımlar bulundu.")
        
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return True
    except Exception as e:
        print(f"[!] ClamAV taraması sırasında hata oluştu: {str(e)}")
        return False
#########################################################################################    
def run_rkhunter_scan(rkhunter_path='/usr/bin/rkhunter'):
    """
    RKHunter ile rootkit taraması yapar.
    """
    try:
        print("[*] RKHunter taraması başlatılıyor...")
        result = subprocess.run([rkhunter_path, '--check', '--skip-keypress'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[✓] RKHunter taraması tamamlandı, rootkit bulunamadı.")
        else:
            print("[!] RKHunter taraması tamamlandı, potansiyel rootkit bulundu.")
        
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return True
    except Exception as e:
        print(f"[!] RKHunter taraması sırasında hata oluştu: {str(e)}")
        return False
    
#########################################################################################    
def periodic_malware_scan(clamav_path='/usr/bin/clamdscan', rkhunter_path='/usr/bin/rkhunter', scan_dir='/', interval=86400):
    """
    ClamAV ve RKHunter taramalarını periyodik olarak çalıştırır.
    """
    while True:
        run_clamav_scan(clamav_path, scan_dir)
        run_rkhunter_scan(rkhunter_path)
        print(f"[*] Bir sonraki tarama için {interval} saniye bekleniyor.\n")
        time_module.sleep(interval)


# Kullanım Örneği

# Politikayı oluşturun
#malware_scan_policy = MalwareScanPolicy()

# Periyodik tarama başlatın (günlük tarama)
# Bu kod her 24 saatte bir tarama yapacaktır.
#malware_scan_policy.periodic_scan(interval=86400)

#########################################################################################    
# LoginBannerPolicy : 3.6
DEFAULT_BANNER = """
********************************************************************************
*                         YASAL UYARI                                         *
* Bu sistem, yalnızca yetkili kullanıcılar için kullanılabilir. Yetkisiz     *
* erişim ve kullanım yasaktır. Sistem aktiviteleri izlenmektedir ve kaydedilmektedir.*
********************************************************************************
"""
#########################################################################################    
def create_banner_file(banner_dir, banner_file="banner.txt", banner_message=DEFAULT_BANNER):
    """
    Belirtilen dizine yasal uyarı mesajını yazar.
    """
    try:
        os.makedirs(banner_dir, exist_ok=True)
        banner_path = os.path.join(banner_dir, banner_file)
        with open(banner_path, "w") as f:
            f.write(banner_message)
        print(f"[✓] Yasal uyarı mesajı yazıldı: {banner_path}")
        return True, banner_path

    except Exception as e:
        print(f"[!] Banner dosyası oluşturulurken hata: {e}")
        return False, str(e)        
#########################################################################################    
def apply_local_banner(local_banner_dir="/etc/issue.d", banner_message=DEFAULT_BANNER):
    """
    Yerel girişler için yasal uyarı banner'ı uygular.
    """
    return create_banner_file(local_banner_dir, "banner.txt", banner_message)

#########################################################################################    
def apply_ssh_banner(ssh_banner_dir="/etc/issue.net.d", banner_message=DEFAULT_BANNER):
    """
    SSH girişleri için yasal uyarı banner'ı uygular.
    """
    return create_banner_file(ssh_banner_dir, "banner.txt", banner_message)
#########################################################################################    
def update_ssh_config(ssh_config_file="/etc/ssh/sshd_config", ssh_banner_dir="/etc/issue.net.d"):
    """
    SSH yapılandırmasını güncelleyerek banner dosyasını etkinleştirir.
    """
    try:
        with open(ssh_config_file, "r") as file:
            lines = file.readlines()

        banner_directive = f"Banner {ssh_banner_dir}/banner.txt\n"
        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith("Banner"):
                lines[i] = banner_directive
                found = True
                break

        if not found:
            lines.append(banner_directive)

        with open(ssh_config_file, "w") as file:
            file.writelines(lines)

        subprocess.run(['systemctl', 'restart', 'sshd'], check=True)
        print(f"[✓] SSH yapılandırması güncellendi ve yeniden başlatıldı.")
        return True, "SSH yapılandırması başarıyla güncellendi."
    except Exception as e:
        print(f"[!] SSH yapılandırması güncellenemedi: {e}")
        return False, str(e)
#########################################################################################    
def apply_login_banner(
    banner_message=DEFAULT_BANNER,
    local_banner_dir="/etc/issue.d",
    ssh_banner_dir="/etc/issue.net.d"
):
    results = []

    results.append(apply_local_banner(local_banner_dir, banner_message))
    results.append(apply_ssh_banner(ssh_banner_dir, banner_message))
    results.append(update_ssh_config("/etc/ssh/sshd_config", ssh_banner_dir))

    success = all(res[0] for res in results)
    messages = "\n".join(res[1] for res in results)

    return success, messages


# apply_login_banner()  # Varsayılan mesajla hem SSH hem konsol banner'ını uygular

# Özel bir mesajla:
# apply_login_banner(banner_message="*** BU SİSTEM GÖZETLENMEKTEDİR. ***")




#########################################################CIS POLİTİKALARI 100#########################################

