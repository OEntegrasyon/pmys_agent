import os
import shutil
import subprocess
import time
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
        success, output = run_command(['sudo', 'mv', temp_path, rule_path])
        if not success:
            return False, f"Modül kural dosyası oluşturulamadı: {output}. 'sudoers' dosyasını kontrol edin."

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
        success , output = run_command(['sudo', 'mv', temp_path, config_file])
        if not success:
            return False, f"Kablosuz modül kural dosyası oluşturulamadı: {output}. 'sudoers' dosyasını kontrol edin."

        # Mevcut yüklü modülleri sistemden kaldırmayı dene
        unloaded_modules = []
        for module in modules_to_disable:
            try:
                success, output = run_command(['sudo', 'modprobe', '-r', module])
                if not success:
                    return False, f"'{module}' modülü kaldırılamadı: {output}. 'sudoers' dosyasını kontrol edin."
                unloaded_modules.append(module)
            except Exception as e:
                return False, f"'{module}' modülü kaldırılırken hata: {e}. 'sudoers' dosyasını kontrol edin."
        
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
        success, output = run_command(['dpkg', '-l', package_name])
        if not success:
            return False, f"Paket durumu kontrol edilirken hata: {output}"
        
        # 'ii' (install ok installed) çıktıda yoksa, paket kurulu değildir. Bu en iyi durumdur.
        if f"ii  {package_name}" not in output:
            return True, f"'{package_name}' paketi sistemde kurulu değil (En güvenli durum)."

        # Adım 2: Paket kurulu ise, servis maskelenmiş mi?
        # 'is-enabled' komutu 'masked' sonucunu da döndürebilir.
        success, output = run_command(['systemctl', 'is-enabled', service_name])
        if not success and "disabled" not in output:
            return False, f"Bluetooth servisi durumu kontrol edilirken hata: {output}"
        is_masked = "masked" in output.strip()

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
        success, output = run_command(['sudo', 'systemctl', 'stop', service_name])
        if not success:
            return False, f"Bluetooth servisi durdurulurken hata: {output}. 'sudoers' dosyasını kontrol edin."

        # Adım 2: Paketi kaldırmayı (purge) dene. Bu en güvenli yöntemdir.
        print(f"'{package_name}' paketi kaldırılmaya çalışılıyor...")
        success, output = run_command(
            ['sudo', 'apt-get', 'purge', '-y', package_name]
        )
        if not success:
            return False, f"'{package_name}' paketi kaldırılırken hata: {output}. 'sudoers' dosyasını kontrol edin."
        return True, f"'{package_name}' paketi ve yapılandırma dosyaları başarıyla kaldırıldı."

    except Exception as e:
        # Eğer 'purge' başarısız olursa (genellikle başka bir paket bağımlı olduğu için),
        # bu durum 'except' bloğunu tetikler. Şimdi alternatif yöntemi uygularız.
        print(f"'{package_name}' paketi kaldırılamadı (muhtemelen başka bir pakete bağımlı). Servis maskeleniyor...")
        try:
            # Adım 3 (Alternatif): Servisi maskele. Bu, 'disable'dan daha güçlüdür.
            success, output = run_command(['sudo', 'systemctl', 'mask', '--now', service_name])
            if not success:
                return False, f"Bluetooth servisi maskelenirken hata: {output}. 'sudoers' dosyasını kontrol edin."
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
        success, output = run_command(['sysctl', sysctl_key])
        if not success:
            return False, f"sysctl '{sysctl_key}' kontrol edilirken hata: {output}"
        # Çıktı formatı: 'net.ipv4.ip_forward = 0' şeklindedir.
        current_value = output.strip().split('=')[-1].strip()

        if current_value == str(expected_value):
            return True, f"'{sysctl_key}' değeri zaten '{expected_value}' olarak doğru ayarlanmış."
        else:
            # Değer farklıysa, apply fonksiyonunu çağır.
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
        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}. 'sudoers' dosyasını kontrol edin."

        # Değeri anında sisteme uygula
        success, output = run_command(['sudo', 'sysctl', '-p', config_path])
        if not success:
            return False, f"sysctl '{key}' uygulanırken hata: {output}. 'sudoers' dosyasını kontrol edin."

        return True, f"'{key}' değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"sysctl '{key}' uygulanırken hata: {e}. 'sudoers' dosyasını kontrol edin."

# ==============================================================================
# == AĞ YAPILANDIRMA POLİTİKASI (PARAMETRELİ) ==============================
# ==============================================================================

def check_network_configuration(username, parameters):
    """
    Ağ yapılandırmasını kontrol eder.
    """
    try:
        if not parameters:
            return False, "Parametre verisi yok."

        expected_ip = parameters.get("expected_ip")
        interface = parameters.get("interface", "ens33")

        if not expected_ip:
            return False, "expected_ip parametresi eksik."

        # IP adreslerini kontrol et
        # DÜZELTME: 'success' ve 'msg' değişkenlerini doğru kullanın.
        success, msg = run_command(["ip", "addr", "show", interface])
        
        # DÜZELTME: Başarı kontrolü 'success' değişkeni ile yapılır.
        if not success:
            return False, f"{interface} arayüzü bulunamadı veya komut başarısız oldu: {msg}"

        # DÜZELTME: İçerik kontrolü 'msg' değişkeninin kendisiyle yapılır.
        if expected_ip in msg:
            return True, f"{interface} üzerinde {expected_ip} IP'si zaten atanmış."

        # IP atanmadıysa, uygula
        return apply_network_configuration(parameters)

    except Exception as e:
        return False, f"Ağ yapılandırması hatası: {str(e)}"
    
def apply_network_configuration(parameters):
    """
    Verilen parametrelere göre ağ yapılandırmasını uygular ve ağı otomatik olarak yeniden başlatır.
    """
    try:
        if not parameters:
            return False, "Uygulanacak ağ yapılandırması parametreleri eksik."

        interface = parameters.get("interface", "ens33")
        expected_ip = parameters.get("expected_ip")
        netmask = parameters.get("netmask", "255.255.255.0")
        gateway = parameters.get("gateway")
        dns = parameters.get("dns", "8.8.8.8 8.8.4.4")

        if not expected_ip or not gateway:
            return False, "IP adresi veya ağ geçidi (gateway) parametresi eksik."

        backup_dir = "/etc/network/backups"
        os.makedirs(backup_dir, exist_ok=True)
        
        interfaces_path = "/etc/network/interfaces"
        
        if os.path.exists(interfaces_path):
            backup_path = os.path.join(backup_dir, f"interfaces.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}")
            shutil.copy(interfaces_path, backup_path)
        else:
            open(interfaces_path, "a").close()

        interfaces_config = f"""# Auto-generated by PMYS Agent
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto {interface}
iface {interface} inet static
    address {expected_ip}
    netmask {netmask}
    gateway {gateway}
    dns-nameservers {dns}
"""
        with open(interfaces_path, "w") as f:
            f.write(interfaces_config)

        # Ağ servisini yeniden başlat
        success, output = run_command(["sudo", "systemctl", "restart", "networking.service"])
        if not success:
            return False, f"Hata: Ağ servisi yeniden başlatılamadı: {output}."
        
        time.sleep(5) # Sistemin yeni ayarları alması için bekle

        # --- SON KONTROL (run_command ile standartlaştırıldı) ---
        check_success, check_output = run_command(["ip", "-4", "addr", "show", interface])
        
        if check_success and f"inet {expected_ip}/" in check_output:
            success_message = f"Başarılı! '{interface}' arayüzü yeni IP adresiyle yapılandırıldı: {expected_ip}"
            return True, success_message
        else:
            failure_message = f"Hata: Yapılandırma sonrası '{interface}' arayüzüne '{expected_ip}' IP'si atanamadı. Çıktı: {check_output}"
            return False, failure_message

    except Exception as e:
        return False, f"Ağ yapılandırması uygulanırken genel bir hata oluştu: {str(e)}"
