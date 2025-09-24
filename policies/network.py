import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command

# ==============================================================================
# == GENEL ÇEKİRDEK MODÜLÜ DEVRE DIŞI BIRAKMA POLİTİKASI (PARAMETRELİ) ===========
# ==============================================================================

# Sunucuda "Politika Tipi" olarak kaydedeceğiniz isim budur.
def check_network_module_disabled(username, parameters):
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
                return apply_network_module_disabled(module_name)
        else:
            # Kural dosyası hiç yok, uygula.
            return apply_network_module_disabled(module_name)

    except Exception as e:
        return False, f"Modül '{module_name}' kontrolünde hata: {e}"

def apply_network_module_disabled(module_name: str) -> tuple[bool, str]:
    """
    Belirtilen çekirdek modülünü /etc/modprobe.d/ içinde bir kural oluşturarak
    devre dışı bırakır. Sadece check_network_module_disabled tarafından çağrılır.
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
    
    except Exception as e:
        return False, f"Modül '{module_name}' devre dışı bırakılırken hata: {e}. 'sudoers' iznini kontrol edin."

# ==============================================================================
# ==  ARAYÜZ VE PROTOKOL POLİTİKALARI ===================================
# ==============================================================================

#  Kablosuz Arayüzleri Devre Dışı Bırak
def disable_wireless_interfaces(username, parameters):
    """
    Sistemde aktif bir kablosuz arayüz modülü olup olmadığını kontrol eder.
    Varsa, devre dışı bırakmak için 'apply' fonksiyonunu çağırır.
    """
    # Bu politika parametre gerektirmez.
    
    # Adım 1: Aktif kablosuz modüllerini tespit et
    wireless_modules = set()
    try:
        # /sys/class/net altında 'wireless' adında bir dizine sahip olan tüm arayüzleri bul
        find_cmd = "find /sys/class/net/ -type d -name wireless"
        interfaces = subprocess.run(find_cmd, shell=True, capture_output=True, text=True).stdout.strip().splitlines()

        if not interfaces:
            # Kablosuz arayüz donanımı bulunamadı, politika zaten karşılanıyor.
            return True, "Sistemde kablosuz arayüz donanımı tespit edilmedi."

        for interface_path in interfaces:
            device_path = os.path.dirname(interface_path)
            driver_link = os.path.join(device_path, "device", "driver", "module")
            if os.path.islink(driver_link):
                module_path = os.path.realpath(driver_link)
                module_name = os.path.basename(module_path)
                wireless_modules.add(module_name)
    
    except Exception as e:
        return False, f"Kablosuz modüller tespit edilirken hata: {e}"

    # Adım 2: Durumu kontrol et ve gerekirse uygula
    if not wireless_modules:
        return True, "Sistemde aktif kablosuz arayüz modülü bulunmuyor."
    else:
        # Eğer bir veya daha fazla modül aktifse, durumu düzeltmek gerekir.
        return apply_wireless_modules_disable(wireless_modules)


def apply_wireless_modules_disable(modules_to_disable: set):
    """
    Tespit edilen kablosuz modüllerin yüklenmesini engeller ve
    mevcut çalışanları sistemden kaldırır.
    """
    config_file = "/etc/modprobe.d/pmys-wifi-blacklist.conf"
    temp_path = "/tmp/pmys-wifi-blacklist.conf"
    
    try:
        # Her bir modül için engelleme kurallarını oluştur
        rules = [f"# PMYS Agent tarafından oluşturuldu - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]
        for module in modules_to_disable:
            rules.append(f"install {module} /bin/true\n")
            rules.append(f"blacklist {module}\n")

        # Kuralları geçici dosyaya yaz
        with open(temp_path, "w") as f:
            f.writelines(rules)
            
        # Dosyayı sudo ile asıl yerine taşı
        subprocess.run(['sudo', 'mv', temp_path, config_file], check=True)

        # Mevcut yüklü modülleri sistemden kaldırmayı dene
        unloaded_modules = []
        for module in modules_to_disable:
            try:
                subprocess.run(['sudo', 'modprobe', '-r', module], check=True, capture_output=True)
                unloaded_modules.append(module)
            except subprocess.CalledProcessError:
                print(f"UYARI: '{module}' modülü meşgul olduğu için kaldırılamadı. Yeniden başlatma sonrası devre dışı kalacaktır.")
                pass
        
        message = f"Kablosuz modüller ({', '.join(modules_to_disable)}) için devre dışı bırakma kuralı oluşturuldu."
        if unloaded_modules:
            message += f" Aktif olanlar ({', '.join(unloaded_modules)}) sistemden kaldırıldı."
            
        return True, message

    except Exception as e:
        return False, f"Kablosuz modüller devre dışı bırakılırken hata: {e}. 'sudoers' dosyasını kontrol edin."


# ------------------------------------------------------------------------------

#  Bluetooth Servisini Devre Dışı Bırak
def disable_bluetooth_service(username, parameters):
    """
    Önce 'bluez' paketinin kurulu olup olmadığını, eğer kuruluysa servisin
    'masked' (maskelenmiş) olup olmadığını kontrol eder.
    """
    # Bu politika parametre gerektirmez.
    package_name = "bluez"
    service_name = "bluetooth.service"
    
    try:
        # Adım 1: Paket kurulu mu?
        pkg_result = subprocess.run(['dpkg', '-l', package_name], capture_output=True, text=True, check=False)
        
        # 'ii' (install ok installed) çıktıda yoksa, paket kurulu değildir. Bu en iyi durumdur.
        if f"ii  {package_name}" not in pkg_result.stdout:
            return True, f"'{package_name}' paketi sistemde kurulu değil (En güvenli durum)."

        # Adım 2: Paket kurulu ise, servis maskelenmiş mi?
        # 'is-enabled' komutu 'masked' sonucunu da döndürebilir.
        enabled_check = subprocess.run(['systemctl', 'is-enabled', service_name], capture_output=True, text=True)
        is_masked = "masked" in enabled_check.stdout.strip()

        if is_masked:
            return True, "Bluetooth servisi zaten maskelenmiş (devre dışı)."
        else:
            # Paket kurulu ve servis maskelenmemişse, düzeltme gerekir.
            return apply_bluetooth_disablement()
            
    except Exception as e:
        return False, f"Bluetooth kontrolünde hata: {e}"

def apply_bluetooth_disablement():
    """
    CIS standardına uygun olarak, önce 'bluez' paketini kaldırmayı dener.
    Başarısız olursa, 'bluetooth.service'i maskeler.
    """
    package_name = "bluez"
    service_name = "bluetooth.service"
    
    try:
        # Adım 1: Servisi her ihtimale karşı durdur
        subprocess.run(['sudo', 'systemctl', 'stop', service_name], check=False)

        # Adım 2: Paketi kaldırmayı (purge) dene. Bu en güvenli yöntemdir.
        print(f"'{package_name}' paketi kaldırılmaya çalışılıyor...")
        purge_result = subprocess.run(
            ['sudo', 'apt-get', 'purge', '-y', package_name],
            check=True, capture_output=True, text=True
        )
        return True, f"'{package_name}' paketi ve yapılandırma dosyaları başarıyla kaldırıldı."

    except subprocess.CalledProcessError:
        # Eğer 'purge' başarısız olursa (genellikle başka bir paket bağımlı olduğu için),
        # bu durum 'except' bloğunu tetikler. Şimdi alternatif yöntemi uygularız.
        print(f"'{package_name}' paketi kaldırılamadı (muhtemelen başka bir pakete bağımlı). Servis maskeleniyor...")
        try:
            # Adım 3 (Alternatif): Servisi maskele. Bu, 'disable'dan daha güçlüdür.
            subprocess.run(['sudo', 'systemctl', 'mask', '--now', service_name], check=True)
            return True, "Bluetooth servisi başarıyla durduruldu ve maskelendi."
        except Exception as e:
            return False, f"Bluetooth servisi maskelenirken hata: {e}"


# ------------------------------------------------------------------------------

#  IPv6 Durumunu Belirle (Sadece Kontrol)
def check_ipv6_status(username, parameters):
    """
    Sistemde IPv6'nın mevcut çalışma durumunu kontrol eder ve raporlar.
    Bu politika bir şeyi değiştirmez, sadece denetim amaçlıdır.
    """
    # Bu politika parametre gerektirmez ve 'apply' fonksiyonu yoktur.
    ipv6_proc_path = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
    
    try:
        # Çekirdek parametresini oku
        if os.path.exists(ipv6_proc_path):
            with open(ipv6_proc_path, 'r') as f:
                status = f.read().strip()
            
            if status == "1":
                # '1' değeri devre dışı anlamına gelir.
                return True, "Denetim Başarılı: IPv6 sistem genelinde devre dışı bırakılmış."
            else:
                # '0' değeri etkin anlamına gelir.
                return True, "Denetim Başarılı: IPv6 sistem genelinde etkin."
        else:
            # Proc dosyası yoksa, çekirdek IPv6 desteği olmadan derlenmiş olabilir.
            return True, "Denetim Başarılı: /proc/sys/net/ipv6 bulunamadı, IPv6 muhtemelen çekirdekte desteklenmiyor veya tamamen kapalı."

    except Exception as e:
        return False, f"IPv6 durumu kontrol edilirken hata: {e}"


# ==============================================================================
# == GENEL SYSCTL YAPILANDIRMA POLİTİKASI (PARAMETRELİ) ========================
# ==============================================================================

def configure_sysctl_parameter(username, parameters):
    """
    Parametre olarak belirtilen bir sysctl anahtarının değerini, yine parametre
    olarak belirtilen beklenen değere ayarlar.
    """
    # Bu politika kullanıcıya özel değil, sistem geneli olduğu için 'username' kullanılmaz.
    
    sysctl_key = parameters.get("key")
    expected_value = parameters.get("value")

    if not sysctl_key or expected_value is None:
        return False, "Politika hatası: 'key' ve 'value' parametreleri zorunludur."

    try:
        # Mevcut sysctl değerini oku
        result = subprocess.run(['sysctl', sysctl_key], capture_output=True, text=True, check=True)
        # Çıktı formatı: 'net.ipv4.ip_forward = 0' şeklindedir.
        current_value = result.stdout.strip().split('=')[-1].strip()

        if current_value == str(expected_value):
            return True, f"'{sysctl_key}' değeri zaten '{expected_value}' olarak doğru ayarlanmış."
        else:
            # Değer farklıysa, apply fonksiyonunu çağır.
            return apply_sysctl_parameter(sysctl_key, str(expected_value))
            
    except subprocess.CalledProcessError:
        # Anahtar hiç var olmayabilir, bu durumda oluşturmayı deneriz.
        return apply_sysctl_parameter(sysctl_key, str(expected_value))
    except Exception as e:
        return False, f"sysctl '{sysctl_key}' kontrolünde hata: {e}"


def apply_sysctl_parameter(key: str, value: str) -> tuple[bool, str]:
    """
    Belirtilen sysctl anahtarına istenen değeri atar ve kalıcı hale getirir.
    """
    # Dosya adında / ve . gibi karakterler olamayacağı için temiz bir isim üretiyoruz.
    config_filename = key.replace('.', '_').replace('/', '_')
    config_path = f"/etc/sysctl.d/99-pmys-{config_filename}.conf"
    temp_path = f"/tmp/99-pmys-{config_filename}.conf"
    config_content = f"{key} = {value}\n"
    
    try:
        # Değeri önce geçici dosyaya yaz
        with open(temp_path, "w") as f:
            f.write(config_content)
        
        # Dosyayı sudo ile kalıcı yerine taşı
        subprocess.run(['sudo', 'mv', temp_path, config_path], check=True)

        # Değeri anında sisteme uygula
        subprocess.run(['sudo', 'sysctl', '-p', config_path], check=True)
        
        return True, f"'{key}' değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"sysctl '{key}' uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."
