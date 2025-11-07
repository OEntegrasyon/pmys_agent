import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command

# ==============================================================================
# == GENEL ÇEKİRDEK MODÜLÜ DEVRE DIŞI BIRAKMA POLİTİKASI (PARAMETRELİ) ===========
# ==============================================================================

def check_network_module_disabled(username, parameters):
    """
    CIS Kuralı: Belirtilen bir çekirdek modülünün (örn: dccp) 
    yüklü OLMADIĞINI ve yüklenemez olduğunu DENETLER.
    """
    module_name = parameters.get("module_name")
    if not module_name:
        return False, "Politika hatası: 'module_name' parametresi belirtilmemiş."

    module_name = module_name.replace('-','_')    
    try:
        lsmod_success, lsmod_output = run_command(['lsmod'])
        if not lsmod_success:
            return False, "lsmod komutu çalıştırılamadı. "
        
        modprobe_config_success, modprobe_config_output = run_command(['modprobe', '--showconfig'])

        if not modprobe_config_success:
            return False, "modprobe --showconfig komutu çalıştırılamadı."
        
        install_check_success, install_check_output = run_command(['modprobe', '-n', '-v', module_name])
        if not install_check_success:
             return False, f"modprobe -n -v {module_name} komutu çalıştırılamadı."

        is_compliant = True 

        if re.search(r"^\s*" + re.escape(module_name) + r"\s+", lsmod_output, re.MULTILINE):
            print(f"Denetim Başarısız: '{module_name}' modülü o an yüklü.")
            is_compliant = False

        # Kontrol B: Modül kara listeye (blacklist) alınmış mı?
        if not re.search(r"^\s*blacklist\s+" + re.escape(module_name) + r"\b", modprobe_config_output, re.MULTILINE):
            print(f"Denetim Başarısız: '{module_name}' modülü 'modprobe --showconfig' çıktısında kara listeye alınmamış.")
            is_compliant = False
            
        # Kontrol C: Modülün yüklenmesi engellenmiş mi (install ... /bin/false)?
        if not re.search(r"^\s*install\s+(/bin/true|/bin/false)\b", install_check_output, re.MULTILINE):
            print(f"Denetim Başarısız: '{module_name}' modülü 'install /bin/false' (veya /bin/true) kuralına sahip değil.")
            is_compliant = False
        
        if is_compliant:
            return True, f"'{module_name}' modülü zaten devre dışı bırakılmış (Uyumlu)."
        else:
            print(f"Denetim: '{module_name}' için kurallar eksik veya modül yüklü. Düzeltme uygulanacak...")
            return apply_network_module_disabled(module_name)

    except Exception as e:
        return False, f"Modül '{module_name}' denetiminde hata: {e}"

def apply_network_module_disabled(module_name: str) -> tuple[bool, str]:
    """
    CIS standardına uygun olarak modülü devre dışı bırakır.
    1. Kalıcı kural dosyası oluşturur (/bin/false ve blacklist).
    2. Modül o an yüklüyse sistemden kaldırır.
    """
    rule_path = f"/etc/modprobe.d/{module_name}-blacklist.conf"
    temp_path = f"/tmp/{module_name}-blacklist.conf.tmp"
    
    rule_content = (
        f"# CIS 3.2.1 uygundur.\n"
        f"install {module_name} /bin/false\n"
        f"blacklist {module_name}\n"
    )

    try:
        # Kuralı önce geçici bir dosyaya yaz
        with open(temp_path, "w") as f:
            f.write(rule_content)

        # sudo ile dosyayı kalıcı yerine taşı
        success, output = run_command(['sudo', 'mv', temp_path, rule_path])
        if not success:
            return False, f"Modül kural dosyası ({rule_path}) oluşturulamadı: {output}"
        
        run_command(['sudo', 'chown', 'root:root', rule_path])
        run_command(['sudo', 'chmod', '0644', rule_path])

        success_unload, out_unload = run_command(['sudo', 'modprobe', '-r', module_name])
        if not success_unload:
            print(f"Bilgi: '{module_name}' modülü kaldırılırken (veya zaten yüklü değilken) uyarı: {out_unload}")

        return True, f"{module_name} modülü başarıyla devre dışı bırakıldı ve kurallar uygulandı."
    
    except Exception as e:
        return False, f"Modül '{module_name}' devre dışı bırakılırken hata: {e}"
# ==============================================================================
# ==  ARAYÜZ VE PROTOKOL POLİTİKALARI ===================================
# ==============================================================================

#  Kablosuz Arayüzleri Devre Dışı Bırak
def disable_wireless_interfaces(username, parameters):
    """
    Sistemdeki kablosuz modülleri tespit eder ve 
    CIS 3.1.2'ye uygun olarak devre dışı bırakılıp bırakılmadığını DENETLER.
    
    Bu fonksiyon, sistemin GERÇEK (çalışan ve yapılandırılmış) durumunu
    lsmod ve modprobe komutlarını kullanarak denetler.
    """
    # Adım 1: Aktif kablosuz modüllerini tespit et
    wireless_modules = set()
    try:
        find_cmd = "find /sys/class/net/ -type d -name wireless"
        interfaces = subprocess.run(find_cmd, shell=True, capture_output=True, text=True, check=False).stdout.strip().splitlines()

        if not interfaces:
            return True, "Sistemde kablosuz arayüz donanımı tespit edilmedi (Uyumlu)."

        for interface_path in interfaces:
            device_path = os.path.dirname(interface_path)
            driver_link = os.path.join(device_path, "device", "driver", "module")
            if os.path.islink(driver_link):
                module_path = os.path.realpath(driver_link)
                module_name = os.path.basename(module_path)
                wireless_modules.add(module_name)
        
        if not wireless_modules:
            return True, "Kablosuz donanım bulundu ancak ilişkili modül tespit edilemedi (Uyumlu)."

    except Exception as e:
        return False, f"Kablosuz modüller tespit edilirken hata: {e}"

    # Adım 2: DENETİM (Audit)
    all_compliant = True 
    
    try:
        lsmod_success, lsmod_output = run_command(['lsmod'])
        if not lsmod_success:
            return False, "lsmod komutu çalıştırılamadı."

        modprobe_config_success, modprobe_config_output = run_command(['modprobe', '--showconfig'])
        if not modprobe_config_success:
            return False, "modprobe --showconfig komutu çalıştırılamadı."

        for module in wireless_modules:
            module_is_ok = True 

            if re.search(r"^\s*" + re.escape(module) + r"\s+", lsmod_output, re.MULTILINE):
                print(f"Denetim Başarısız: '{module}' modülü o an yüklü.")
                all_compliant = False
                module_is_ok = False 

            if not re.search(r"^\s*blacklist\s+" + re.escape(module) + r"\b", modprobe_config_output, re.MULTILINE):
                print(f"Denetim Başarısız: '{module}' modülü 'modprobe --showconfig' çıktısında kara listeye alınmamış.")
                all_compliant = False
                module_is_ok = False 

            install_check_success, install_check_output = run_command(['modprobe', '-n', '-v', module])
            if not install_check_success:
                 return False, f"modprobe -n -v {module} komutu çalıştırılamadı."
            
            if not re.search(r"^\s*install\s+(/bin/true|/bin/false)\b", install_check_output, re.MULTILINE):
                print(f"Denetim Başarısız: '{module}' modülü 'install /bin/false' (veya /bin/true) kuralına sahip değil.")
                all_compliant = False
                module_is_ok = False 

            if module_is_ok:
                 print(f"Denetim Başarılı: '{module}' modülü tüm kurallara uyuyor.")

    except Exception as e:
        return False, f"Kablosuz modül kuralları denetlenirken hata: {e}"

    if all_compliant:
        return True, f"Tüm kablosuz modüller ({', '.join(wireless_modules)}) zaten devre dışı bırakılmış (Uyumlu)."
    else:
        print(f"Denetim: Uyumsuz kablosuz modüller bulundu. Düzeltme uygulanacak...")
        return apply_wireless_modules_disable(wireless_modules)

CONFIG_FILE = "/etc/modprobe.d/wifi-blacklist.conf"

def apply_wireless_modules_disable(modules_to_disable: set):
    """
    Tespit edilen kablosuz modüller için kalıcı engelleme kuralları oluşturur
    ve modülleri sistemden kaldırır.
    """
    temp_path = "/tmp/wifi-blacklist.conf.tmp"
    
    try:
        rules = [f"# Server tarafından oluşturuldu - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]
        for module in modules_to_disable:
            rules.append(f"install {module} /bin/false\n")
            rules.append(f"blacklist {module}\n")

        with open(temp_path, "w") as f:
            f.writelines(rules)
            
        success, output = run_command(['sudo', 'mv', temp_path, CONFIG_FILE])
        if not success:
            return False, f"Kablosuz modül kural dosyası oluşturulamadı: {output}"

        for module in modules_to_disable:
            is_loaded_check = run_command(['lsmod'])
            if is_loaded_check[0] and module in is_loaded_check[1]:
                unload_success, unload_out = run_command(['sudo', 'modprobe', '-r', module])
                if not unload_success:
                    print(f"Uyarı: '{module}' modülü o an çalışırken kaldırılamadı: {unload_out}")
        
        return True, f"Kablosuz modüller ({', '.join(modules_to_disable)}) başarıyla devre dışı bırakıldı."

    except Exception as e:
        return False, f"Kablosuz modüller devre dışı bırakılırken hata: {e}"

# ------------------------------------------------------------------------------

#  Bluetooth Servisini Devre Dışı Bırak
def disable_bluetooth_service(username, parameters):
    """
    CIS 3.1.3: Bluetooth servisinin durumunu denetler.
    Eğer servis 'masked' değilse, 'apply_bluetooth_mask' fonksiyonunu çağırır.
    """
    service_name = "bluetooth.service"
    
    try:
        # 'is-enabled' komutu 'masked' durumunu da raporlar.
        # Bu komut, servis dosyası (paket) yoksa hata verir.
        success, output = run_command(['systemctl', 'is-enabled', service_name])

        if success:
            if output.strip() == "masked":
                return True, "Bluetooth servisi zaten maskelenmiş (Uyumlu)."
            else:
                # Servis var ama maskelenmemiş (örn: 'enabled', 'disabled')
                return apply_bluetooth_disablement(parameters)
        else:
            return True, "Bluetooth servisi bulunamadı (Paket muhtemelen kurulu değil) (Uyumlu)."
            
    except Exception as e:
        return False, f"Bluetooth servisi denetlenirken hata: {e}"

def apply_bluetooth_disablement():

    service_name = "bluetooth.service"
    try:
        # '--now' komutu servisi o an durdurur VE kalıcı olarak maskeler.
        success, output = run_command(['sudo', 'systemctl', 'mask', '--now', service_name])
        
        if success:
            return True, "Bluetooth servisi başarıyla durduruldu ve maskelendi."
        else:
            return False, f"Bluetooth servisi maskelenirken hata: {output}. 'sudoers' dosyasını kontrol edin."

    except Exception as e:
        return False, f"Bluetooth servisi maskelenirken hata: {e}"


# ------------------------------------------------------------------------------

#  IPv6 Durumunu Belirle Politikası 1: IPv6 enable eder
def check_ipv6_status(username, parameters):
    """
    CIS 3.1.1: IPv6'nın etkin ('0') olup olmadığını denetler.
    Eğer devre dışıysa ('1'), 'apply_ipv6_enable' fonksiyonunu çağırır.
    """
    all_path = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
    def_path = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
    
    try:
        # 1. Denetim (Audit): Gerekli proc dosyaları var mı?
        if not os.path.exists(all_path) or not os.path.exists(def_path):
            return True, "IPv6 çekirdekte desteklenmiyor veya /proc arayüzü yok."

        # 2. Denetim (Audit): Mevcut durumu oku
        with open(all_path, 'r') as f: all_status = f.read().strip()
        with open(def_path, 'r') as f: def_status = f.read().strip()
            
        # 3. Karar: Her ikisi de '0' (etkin) mi?
        if all_status == "0" and def_status == "0":
            return True, "IPv6 zaten sistem genelinde etkin (Uyumlu)."
        else:
            # Durum '1' (devre dışı).
            return apply_ipv6_enable(parameters)

    except Exception as e:
        return False, f"IPv6 durumu (enable) kontrol edilirken hata: {e}"
    
def apply_ipv6_enable(parameters):
    """
    IPv6'yı etkinleştirmek ('0' yapmak) için kalıcı sysctl ayarlarını uygular.
    """
    # Ayarların kalıcı olması için .conf dosyası oluşturulur.
    config_file = "/etc/sysctl.d/99-ipv6-policy.conf"
    temp_path = "/tmp/99-ipv6-policy.conf.tmp"
    config_content = (
        "# Server tarafından CIS 3.1.1 uyarınca yönetilmektedir.\n"
        "# IPv6 Etkinleştirildi.\n"
        "net.ipv6.conf.all.disable_ipv6 = 0\n"
        "net.ipv6.conf.default.disable_ipv6 = 0\n"
    )
    
    try:
        # 1. Ayar dosyasını güvenli bir yere yaz
        with open(temp_path, "w") as f:
            f.write(config_content)
        
        # 2. Dosyayı kalıcı yerine taşı ve izinlerini ayarla
        success_mv, out_mv = run_command(['sudo', 'mv', temp_path, config_file])
        if not success_mv:
            return False, f"IPv6 (enable) yapılandırma dosyası taşınamadı: {out_mv}"
        
        run_command(['sudo', 'chown', 'root:root', config_file])
        run_command(['sudo', 'chmod', '0644', config_file])

        # 3. Ayarları SİSTEMİ YENİDEN BAŞLATMADAN hemen uygula
        # 'sysctl -w' kullanmak, değişikliği o anki çalışan çekirdeğe yazar.
        success_all, out_all = run_command(['sudo', 'sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'])
        success_def, out_def = run_command(['sudo', 'sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'])

        if not success_all or not success_def:
             return False, f"sysctl (enable) ayarları anlık uygulanamadı: {out_all} | {out_def}"
        
        return True, "IPv6 başarıyla etkinleştirildi ve ayarlar kalıcı hale getirildi."
        
    except Exception as e:
        return False, f"IPv6 etkinleştirilirken hata: {e}"

# ------------------------------------------------------------------------------

#  IPv6 Durumunu Belirle Politikası 2: IPv6 disable eder

def ensure_ipv6_disabled(username, parameters):

    all_path = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
    def_path = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
    
    try:
        # 1. Denetim (Audit): Gerekli proc dosyaları var mı?
        if not os.path.exists(all_path) or not os.path.exists(def_path):
            return True, "IPv6 çekirdekte desteklenmiyor (Uyumlu)."

        # 2. Denetim (Audit): Mevcut durumu oku
        with open(all_path, 'r') as f: all_status = f.read().strip()
        with open(def_path, 'r') as f: def_status = f.read().strip()
            
        # 3. Karar: Her ikisi de '1' (devre dışı) mı?
        if all_status == "1" and def_status == "1":
            return True, "IPv6 zaten sistem genelinde devre dışı (Uyumlu)."
        else:
            return apply_ipv6_disable(parameters)

    except Exception as e:
        return False, f"IPv6 durumu (disable) kontrol edilirken hata: {e}"
    
def apply_ipv6_disable(parameters):
    """
    IPv6'yı devre dışı bırakmak ('1' yapmak) için kalıcı sysctl ayarlarını uygular.
    """
    # Dosya adı 1. Politika ile aynı. Bu kasıtlıdır.
    # Bu politika atanırsa, diğer politikanın dosyasının ÜZERİNE YAZAR.
    config_file = "/etc/sysctl.d/99-ipv6-policy.conf"
    temp_path = "/tmp/99-ipv6-policy.conf.tmp"
    config_content = (
        "# Server tarafından (Yönetici İsteğiyle) yönetilmektedir.\n"
        "# IPv6 Devre Dışı Bırakıldı.\n"
        "net.ipv6.conf.all.disable_ipv6 = 1\n"
        "net.ipv6.conf.default.disable_ipv6 = 1\n"
    )
    
    try:
        # 1. Ayar dosyasını güvenli bir yere yaz
        with open(temp_path, "w") as f:
            f.write(config_content)
        
        # 2. Dosyayı kalıcı yerine taşı ve izinlerini ayarla
        success_mv, out_mv = run_command(['sudo', 'mv', temp_path, config_file])
        if not success_mv:
            return False, f"IPv6 (disable) yapılandırma dosyası taşınamadı: {out_mv}"
        
        run_command(['sudo', 'chown', 'root:root', config_file])
        run_command(['sudo', 'chmod', '0644', config_file])

        # 3. Ayarları SİSTEMİ YENİDEN BAŞLATMADAN hemen uygula
        success_all, out_all = run_command(['sudo', 'sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1'])
        success_def, out_def = run_command(['sudo', 'sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=1'])

        if not success_all or not success_def:
             return False, f"sysctl (disable) ayarları anlık uygulanamadı: {out_all} | {out_def}"
        
        return True, "IPv6 başarıyla devre dışı bırakıldı ve ayarlar kalıcı hale getirildi."
        
    except Exception as e:
        return False, f"IPv6 devre dışı bırakılırken hata: {e}"

# ==============================================================================
# == GENEL SYSCTL YAPILANDIRMA POLİTİKASI (PARAMETRELİ) ========================
# ==============================================================================
def _is_ipv6_disabled_for_sysctl():
    """
    Sistemde IPv6'nın sysctl ayarları için devre dışı olup olmadığını kontrol eder.
    """
    # /proc/sys/net/ipv6 dizini yoksa, sysctl ayarları da yoktur.
    return not os.path.exists("/proc/sys/net/ipv6/conf/all")

def configure_sysctl_parameter(username, parameters):
    """
    Birden fazla sysctl anahtarını (listedeki) tek bir beklenen değere göre
    denetler ve gerekirse düzeltir. (Fonksiyon adı aynı kaldı)
    """
    sysctl_keys = parameters.get("keys") 
    expected_value = parameters.get("value")

    # Parametreleri doğrula
    if not sysctl_keys or not isinstance(sysctl_keys, list) or expected_value is None:
        return False, "Politika hatası: 'keys' (liste olarak) ve 'value' parametreleri zorunludur."
     
    expected_value = str(expected_value) # Gelen '1' (int) değerini '1' (str) yap

    all_successful = True
    all_messages = []
    
    # 'keys' listesindeki her bir anahtar için döngü
    for sysctl_key in sysctl_keys:
        
        # Anahtarın geçerli bir string olduğundan emin ol
        if not sysctl_key or not isinstance(sysctl_key, str) or sysctl_key.strip() == "":
            all_messages.append("[Geçersiz Anahtar]: Parametre listesindeki bir anahtar boş.")
            all_successful = False
            continue 

        try:
            if "net.ipv6." in sysctl_key:
                if _is_ipv6_disabled_for_sysctl():
                    all_messages.append(f"[{sysctl_key}]: Denetim atlandı (IPv6 devre dışı - Uyumlu/NA).")
                    continue # Bu anahtar başarılı (NA), döngüde sonrakine geç

            # Orijinal kodunuzdaki subprocess çalıştırma
            proc = subprocess.run(
                ['sysctl', '-n', sysctl_key], 
                capture_output=True, text=True, check=False
            )
            
            if proc.returncode != 0:
                # 'No such file' hatası (örn. IPv6 kapalıyken) bir hata değil, NA durumudur.
                if ("No such file" in proc.stderr or "does not exist" in proc.stderr):
                    all_messages.append(f"[{sysctl_key}]: Denetim atlandı (Ayar mevcut değil - Uyumlu/NA).")
                    continue # Başarılı sayılır, sonrakine geç
                else:
                    # Gerçek bir hata
                    all_messages.append(f"[{sysctl_key}]: sysctl kontrol edilirken hata: {proc.stderr.strip()}")
                    all_successful = False
                    continue # Başarısız, sonrakine geç
            
            current_value = proc.stdout.strip()

            # Orijinal kodunuzdaki değer karşılaştırması
            if current_value == expected_value:
                all_messages.append(f"[{sysctl_key}]: Değer zaten '{expected_value}' olarak doğru ayarlanmış.")
                # all_successful = True (zaten öyle)
            else:
                # Orijinal kodunuzdaki apply (düzeltme) çağrısı
                success, message = apply_sysctl_parameter(sysctl_key, expected_value)
                
                all_messages.append(f"[{sysctl_key}]: {message}")
                if not success:
                    all_successful = False # Eğer herhangi biri başarısızsa, toplam sonuç başarısızdır
                    
        except Exception as e:
            all_messages.append(f"[{sysctl_key}]: sysctl kontrolünde genel hata: {e}")
            all_successful = False
     
 
    return all_successful, "\n".join(all_messages)
    
def apply_sysctl_parameter(key: str, value: str) -> tuple[bool, str]:
    """
    Belirtilen sysctl anahtarına istenen değeri atar, kalıcı hale getirir
    ve yönlendirme önbelleğini temizler.
    """
    config_filename = key.replace('.', '_').replace('/', '_')
    config_path = f"/etc/sysctl.d/60-{config_filename}.conf"
    temp_path = f"/tmp/60-{config_filename}.conf.tmp"
    
    config_content = f"# Server tarafından yönetilmektedir: {key}\n{key} = {value}\n"
    
    try:
        with open(temp_path, "w") as f:
            f.write(config_content)
        
        success, output = run_command(['sudo', 'mv', temp_path, config_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}."
        
        run_command(['sudo', 'chown', 'root:root', config_path])
        run_command(['sudo', 'chmod', '0644', config_path])

        success, output = run_command(['sudo', 'sysctl', '-w', f"{key}={value}"])
        if not success:
            if "net.ipv6." in key and "No such file" in output:
                print(f"Bilgi: '{key}' anlık uygulanamadı (IPv6 kapalı).")
            else:
                return False, f"sysctl -w '{key}' uygulanırken hata: {output}."

        if "net.ipv4." in key:
            run_command(['sudo', 'sysctl', '-w', 'net.ipv4.route.flush=1'])
        elif "net.ipv6." in key:
            run_command(['sudo', 'sysctl', '-w', 'net.ipv6.route.flush=1'])

        return True, f"'{key}' değeri başarıyla '{value}' olarak ayarlandı."

    except Exception as e:
        return False, f"sysctl '{key}' uygulanırken hata: {e}."
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
        success, msg = run_command(["ip", "addr", "show", interface])
        
        if not success:
            return False, f"{interface} arayüzü bulunamadı veya komut başarısız oldu: {msg}"

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
