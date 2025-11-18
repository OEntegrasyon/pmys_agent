import json
import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
import re



# ==============================================================================
# == PAKET YÖNETİCİSİ (APT) YAPILANDIRMA POLİTİKASI ============================
# ==============================================================================
def _normalize_content_to_set(content_str, line_separator=';'):
    """
    Bir depo içeriği string'ini alır, yorumları ve boş satırları atar,
    karşılaştırma için bir 'set' (küme) döndürür.
    """
    # Sunucudan geliyorsa ';' (varsayılan), dosyadan okunuyorsa '\n' kullan
    if line_separator == ';':
        content = content_str.replace(line_separator, '\n')
    else:
        content = content_str
        
    lines = {
        line.strip() 
        for line in content.splitlines() 
        if line.strip() and not line.strip().startswith('#')
    }
    return lines

def check_secure_apt_repositories(username, parameters):
    """
    CIS 1.2.1.2 Politikasını tam olarak denetler.
    Hem /etc/apt/sources.list dosyasını hem de /etc/apt/sources.list.d/
    dizinindeki TÜM dosyaları, sunucudaki "beyaz liste" (allow-list) ile karşılaştırır.
    """
    SOURCES_LIST_PATH = "/etc/apt/sources.list"
    SOURCES_DIR_PATH = "/etc/apt/sources.list.d"

    try:
        # parametrelerini al ve işle
        main_content_str = parameters.get("main_repo_content")
        sources_d_json = parameters.get("sources_d_files_json")

        if not main_content_str or sources_d_json is None: # sources_d_files_json boş bir JSON olabilir ('{}'), ama None olamaz.
            return False, "Politika hatası: 'main_repo_content' veya 'sources_d_files_json' parametreleri eksik."

        # Beklenen (onaylı) içeriği parse et
        expected_main_lines = _normalize_content_to_set(main_content_str, line_separator=';')
        
        try:
            # Sunucudan gelen JSON string'ini Python sözlüğüne (dictionary) çevir
            expected_sources_d = json.loads(sources_d_json)
        except json.JSONDecodeError:
            return False, f"Politika hatası: 'sources_d_files_json' geçerli bir JSON formatında değil."

        # Ana sources.list dosyasını kontrol et
        if not os.path.exists(SOURCES_LIST_PATH):
             print(f"Denetim: {SOURCES_LIST_PATH} dosyası eksik. Düzeltme uygulanacak.")
             return apply_secure_apt_repositories(username, parameters) # 'username' argümanını da yolla

        with open(SOURCES_LIST_PATH, "r") as f:
            current_main_content = f.read()
        
        current_main_lines = _normalize_content_to_set(current_main_content, line_separator='\n')

        if current_main_lines != expected_main_lines:
            print(f"Denetim: {SOURCES_LIST_PATH} içeriği farklı. Düzeltme uygulanacak.")
            return apply_secure_apt_repositories(username, parameters)

        # sources.list.d dizinini kontrol et
        if not os.path.isdir(SOURCES_DIR_PATH):
             os.makedirs(SOURCES_DIR_PATH) 
             
        expected_filenames = set(expected_sources_d.keys())
        
        # Sadece .list ve .sources dosyalarını dikkate al 
        current_filenames = set(f for f in os.listdir(SOURCES_DIR_PATH) if f.endswith(('.list', '.sources')))
        
        if current_filenames != expected_filenames:
            print(f"Denetim: sources.list.d dizinindeki dosya listesi eşleşmiyor. Düzeltme uygulanacak.")
            print(f" - Beklenen: {expected_filenames}")
            print(f" - Mevcut: {current_filenames}")
            return apply_secure_apt_repositories(username, parameters)

        # Dosya listesi eşleşiyorsa, içerikleri kontrol et
        for filename in expected_filenames:
            file_path = os.path.join(SOURCES_DIR_PATH, filename)
            with open(file_path, "r") as f:
                current_file_content = f.read()
            
            current_file_lines = _normalize_content_to_set(current_file_content, line_separator='\n')
            expected_file_lines = _normalize_content_to_set(expected_sources_d[filename], line_separator=';')
            
            if current_file_lines != expected_file_lines:
                print(f"Denetim: {file_path} dosyasının içeriği farklı. Düzeltme uygulanacak.")
                return apply_secure_apt_repositories(username, parameters)

        return True, "Tüm APT depoları (sources.list ve sources.list.d) standartlara uygun."

    except Exception as e:
        return False, f"APT depo denetiminde genel hata: {e}"

def apply_secure_apt_repositories(username, parameters):
    """
    /etc/apt/sources.list dosyasını ve /etc/apt/sources.list.d/ dizinini,
    sunucudan gelen "beyaz liste" (allow-list) ile tam olarak eşleşecek şekilde
    güvenli bir şekilde yeniden yapılandırır.
    """
    SOURCES_LIST_PATH = "/etc/apt/sources.list"
    SOURCES_DIR_PATH = "/etc/apt/sources.list.d"
    
    try:
        # 1. Sunucu parametrelerini al ve işle
        main_content_str = parameters.get("main_repo_content")
        sources_d_json = parameters.get("sources_d_files_json")

        if not main_content_str or sources_d_json is None:
            return False, "Politika hatası: 'main_repo_content' veya 'sources_d_files_json' parametreleri eksik."

        expected_main_content = main_content_str.replace(';', '\n')
        
        try:
            expected_sources_d = json.loads(sources_d_json)
        except json.JSONDecodeError:
            return False, f"Politika hatası: 'sources_d_files_json' geçerli bir JSON formatında değil."

        # 2. Ana sources.list dosyasını uygula
        temp_path_main = "/tmp/sources.list.new"
        
        # Yedekleme
        if os.path.exists(SOURCES_LIST_PATH):
            backup_path = f"/etc/apt/sources.list.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            success, output = run_command(['sudo', 'cp', SOURCES_LIST_PATH, backup_path])
            if not success:
                return False, f"Yedek dosya ({SOURCES_LIST_PATH}) oluşturulurken hata: {output}."
        
        # Yeni dosyayı yaz
        with open(temp_path_main, "w") as f:
            f.write(expected_main_content)
            if not expected_main_content.endswith('\n'):
                f.write('\n')
        
        # Atomik olarak taşı
        success, output = run_command(['sudo', 'mv', temp_path_main, SOURCES_LIST_PATH])
        if not success:
            return False, f"Geçici dosya ({temp_path_main}) taşınırken hata: {output}."

        # 3. sources.list.d dizinini uygula
        if not os.path.isdir(SOURCES_DIR_PATH):
             os.makedirs(SOURCES_DIR_PATH)
             
        expected_filenames = set(expected_sources_d.keys())
        current_filenames = set(f for f in os.listdir(SOURCES_DIR_PATH) if f.endswith(('.list', '.sources')))
        
        # Yetkisiz (Rogue) dosyaları sil
        files_to_delete = current_filenames - expected_filenames
        for filename in files_to_delete:
            file_path = os.path.join(SOURCES_DIR_PATH, filename)
            print(f"Uygulama: Yetkisiz depo dosyası siliniyor: {file_path}")
            success, output = run_command(['sudo', 'rm', file_path])
            if not success:
                return False, f"Yetkisiz depo dosyası ({file_path}) silinirken hata: {output}."

        # Onaylı dosyaları yaz/güncelle
        for filename, content_str in expected_sources_d.items():
            content_to_write = content_str.replace(';', '\n')
            temp_path_d = f"/tmp/{filename}.new"
            final_path = os.path.join(SOURCES_DIR_PATH, filename)
            
            with open(temp_path_d, "w") as f:
                f.write(content_to_write)
                if not content_to_write.endswith('\n'):
                    f.write('\n')
            
            success, output = run_command(['sudo', 'mv', temp_path_d, final_path])
            if not success:
                return False, f"Onaylı depo dosyası ({final_path}) yazılırken hata: {output}."

        # Depoları güncelle
        print("Depo listeleri güncellendi, 'apt-get update' çalıştırılıyor...")
        success, output = run_command(['sudo', 'apt-get', 'update'], timeout=120)
        if not success:
            return False, f"'apt-get update' çalıştırılırken hata (Bu, eksik GPG anahtarı gibi başka bir politika sorununu gösterebilir): {output}."

        return True, "Paket yöneticisi depoları (sources.list ve sources.list.d) başarıyla standart yapılandırmaya getirildi."

    except Exception as e:
        return False, f"APT depoları uygulanırken genel hata: {e}"

# ==============================================================================
# == GPG ANAHTAR POLİTİKASI =====================================
# ==============================================================================
def audit_gpg_keys(username, parameters):
    """
    Sistemdeki tüm APT GPG anahtarlarının parmak izlerini, parametre olarak verilen
    onaylı parmak izi listesiyle karşılaştırır. Hem yetkisiz hem de eksik anahtarları raporlar.
    Bu politika, otomatik düzeltme (apply) yapmaz, sadece denetler.
    """
    
    fingerprints_param = parameters.get("allowed_fingerprints")
    if not fingerprints_param:
        return False, "Politika hatası: 'allowed_fingerprints' parametresi ile onaylı anahtar listesi belirtilmemiş."
    
    allowed_fingerprints = []
    if isinstance(fingerprints_param, list):
        allowed_fingerprints = fingerprints_param
    elif isinstance(fingerprints_param, str):
        allowed_fingerprints = [fp.strip() for fp in fingerprints_param.split(',') if fp.strip()]
    
    if not allowed_fingerprints:
        return False, "Onaylı anahtar parmak izi listesi boş."

    allowed_set = set(allowed_fingerprints)
    
    # Sistemdeki anahtar konumlarını tara
    keyring_paths = ["/etc/apt/keyrings", "/usr/share/keyrings", "/etc/apt/trusted.gpg.d"]
    found_fingerprints = set()
    
    try:
        for path in keyring_paths:
            if os.path.isdir(path):
                for filename in os.listdir(path):
                    key_file = os.path.join(path, filename)
                    gpg_cmd = []
                                        
                    if filename.endswith(".gpg"):
                        # .gpg (anahtarlık) dosyaları için
                        gpg_cmd = [
                            'gpg', '--batch', '--no-tty', 
                            '--no-default-keyring', 
                            '--keyring', key_file, 
                            '--list-keys',        
                            '--with-colons', '--with-fingerprint'
                        ]
                    elif filename.endswith(".asc"):
                        # .asc (tekil anahtar) dosyaları için 
                        gpg_cmd = [
                            'gpg', '--batch', '--no-tty', 
                            '--no-default-keyring',
                            '--with-fingerprint',   
                            key_file
                        ]
                    else:
                        continue # .gpg veya .asc değilse atla

                    success, output = run_command(gpg_cmd)

                 
                    if not success:
                        # Eğer gpg komutu başarısız olduysa denetimi durdur ve hata raporla.
                        return False, f"HATA: '{key_file}' dosyası okunamadı veya bozuk. gpg çıktısı: {output}"
               

                    for line in output.splitlines():
                        if line.startswith("fpr"):
                            fingerprint = line.strip().split(':')[9]
                            if fingerprint:
                                found_fingerprints.add(fingerprint)

        if not found_fingerprints:
            if not allowed_set:
                 return True, "Sistemde GPG anahtarı bulunamadı ve onaylı listede de anahtar yoktu. (Uyumlu)"

        unauthorized_keys = found_fingerprints - allowed_set
        if unauthorized_keys:
            return False, f"Yetkisiz GPG anahtarları tespit edildi: {', '.join(unauthorized_keys)}"

        missing_keys = allowed_set - found_fingerprints
        if missing_keys:
            return False, f"Onaylı listede olması gereken şu anahtarlar sistemde bulunamadı: {', '.join(missing_keys)}"

        return True, "Tüm GPG anahtarları onaylı listede ve eksik anahtar yok."

    except Exception as e:
        return False, f"GPG anahtarları denetlenirken bir hata oluştu: {e}"
# ------------------------------------------------------------------------------

# ==============================================================================
# CIS 1.2.2.1: GÜNCELLEME VE YAMA DENETİMİ POLİTİKASI
# ==============================================================================

def audit_pending_updates(username, parameters):
    """
    CIS 1.2.2.1 
    Sistemin güncel olup olmadığını denetler.     
    """
    
    try:
        # Depo listesini yenile (apt update)
        success, output = run_command(['sudo', 'apt-get', 'update'], timeout=120)
        
        if not success:
            return False, f"'apt-get update' başarısız oldu. Depo yapılandırmasını (Policy 1.2.1.2) veya internet bağlantısını kontrol edin. Hata: {output}"

        # Yükseltilebilecek paketleri listele
        success, output = run_command(['sudo', 'apt', 'list', '--upgradable'])
        
        if not success:
            return False, f"'apt list --upgradable' komutu çalıştırılamadı. Hata: {output}"

        # Çıktıyı analiz et     
        lines = output.strip().splitlines()
        package_lines = [line for line in lines if not line.strip().startswith('Listing...') and not line.strip().startswith('Listeleme...') and not line.strip().startswith('WARNING:')]        
        package_count = len(package_lines)

        if package_count == 0:
            return True, "Sistem güncel. Bekleyen yama yok."
        else:
            sample_packages = [line.split('/')[0] for line in package_lines[:3]]
            return False, f"Sistemde {package_count} adet bekleyen güncelleme/yama var. (Örn: {', '.join(sample_packages)}...)"

    except Exception as e:
        return False, f"Güncelleme denetimi sırasında genel hata: {e}"


# ==============================================================================
# Paket Sürüm Sabitleme

def check_package_pinning(username, parameters):
    try:
        package_name = parameters.get("package")
        version = parameters.get("version")

        if not package_name or not version:
            return False, "Paket adı veya sürüm belirtilmedi."

        success , output = run_command(["apt-cache", "policy", package_name])

        if "1001" in output and version in output:
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

        # Pinleme dosyası oluşturur
        pin_file = f"/etc/apt/preferences.d/{package_name}.pref"
        with open(pin_file, "w") as f:
            f.write(f"Package: {package_name}\n")
            f.write(f"Pin: version {version}\n")
            f.write(f"Pin-Priority: 1001\n")

        # Paketi kilitler
        subprocess.run(["apt-mark", "hold", package_name], check=True)

        # Pinleme başarı kontrolü
        success, output=run_command(["apt-cache", "policy", package_name])

        if "1001" in output and version in output:
            return True, f"{package_name} paketi {version} sürümüne sabitlendi ve güncellemesi engellendi."
        else:
            return False, f"{package_name} için pinleme başarısız. Elle kontrol ediniz."
    except Exception as e:
        return False, f"Hata: {str(e)}"
    
# ==============================================================================


def check_required_software(username, parameters):
    """
    Politika parametrelerinde belirtilen 'required' paketlerin sistemde kurulu olup olmadığını kontrol eder.
    Eksik paketler varsa, kurulum için apply fonksiyonunu tetikler.
    """
    required_param = parameters.get("required", [])
    if isinstance(required_param, str):
        required_packages = [required_param]
    elif isinstance(required_param, list):
        required_packages = required_param
    else:
        return False, f"Hata: 'required' parametresi bir metin (string) veya liste (array) olmalıdır. Gelen tip: {type(required_param)}"
    
    
    if not required_packages:
        return True, "Kurulum için belirtilmiş bir paket listesi bulunmuyor."

    missing_packages = []
    try:
        for package in required_packages:
            success, output = run_command(["dpkg", "-l", package])
            # Komut başarısız olduysa veya çıktıda 'ii' (installed) durumu yoksa, paketi eksik olarak işaretler
            if not success or f"ii  {package}" not in output:
                missing_packages.append(package)

        if not missing_packages:
            return True, "Gerekli tüm yazılımlar zaten kurulu."
        
        return apply_required_software(missing_packages)
        
    except Exception as e:
        return False, f"Yazılım kontrolü sırasında hata oluştu: {str(e)}"

def apply_required_software(missing_packages):
    """
    Eksik olan paketlerin kurulumunu 'sudo apt-get install' komutuyla gerçekleştirir.
    """
    messages = []
    
    update_success, update_output = run_command(["sudo", "apt-get", "update"])
    if not update_success:
        return False, f"apt-get update başarısız oldu: {update_output}"

    try:
        for package in missing_packages:
            install_success, install_output = run_command(["sudo", "apt-get", "install", "-y", package])
            
            if install_success:
                messages.append(f"'{package}' başarıyla yüklendi.")
            else:
                messages.append(f"'{package}' yüklenemedi. Hata: {install_output}")

        return True, " ".join(messages)
        
    except Exception as e:
        return False, f"Yazılım kurulumu sırasında hata oluştu: {str(e)}"