import os
import subprocess
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command



# ==============================================================================
# == PAKET YÖNETİCİSİ (APT) YAPILANDIRMA POLİTİKASI ============================
# ==============================================================================
def check_secure_apt_repositories(username, parameters):
    """
    /etc/apt/sources.list dosyasının içeriğini, sunucudan gelen
    standart içerikle karşılaştırır. Farklıysa, apply fonksiyonunu çağırır.
    """
    expected_content_from_server = parameters.get("repo_content", "")
    if not expected_content_from_server:
        return False, "Politika hatası: 'repo_content' parametresi belirtilmemiş."

    # ';' karakterini gerçek yeni satıra ('\n') çevirerek doğru formatı oluştur
    expected_content = expected_content_from_server.replace(';', '\n')
    sources_path = "/etc/apt/sources.list"
    
    try:
        if not os.path.exists(sources_path):
            return apply_secure_apt_repositories(parameters)

        with open(sources_path, "r") as f:
            current_content = f.read()

        current_repos = {line.strip() for line in current_content.splitlines() if line.strip() and not line.strip().startswith('#')}
        expected_repos = {line.strip() for line in expected_content.splitlines() if line.strip() and not line.strip().startswith('#')}

        if current_repos == expected_repos:
            return True, "Paket yöneticisi (apt) depoları zaten standartlara uygun."
        else:
            return apply_secure_apt_repositories(parameters)
    except Exception as e:
        return False, f"APT depo kontrolünde hata: {e}"

def apply_secure_apt_repositories(parameters):
    """
    /etc/apt/sources.list dosyasını, parametre olarak verilen standart içerikle
    güvenli bir şekilde değiştirir ve 'apt update' komutunu çalıştırır.
    """
    expected_content_from_server = parameters.get("repo_content", "")
    if not expected_content_from_server:
        return False, "Politika hatası: 'repo_content' parametresi boş olamaz."

    sources_path = "/etc/apt/sources.list"
    temp_path = "/tmp/sources.list.new"
    
    try:
        # --- TEK VE BASİT DÖNÜŞÜM ---
        # Gelen metindeki ';' karakterini gerçek yeni satır '\n' ile değiştiriyoruz.
        content_to_write = expected_content_from_server.replace(';', '\n')
        
        # Yedekleme
        if os.path.exists(sources_path):
            backup_path = f"/etc/apt/sources.list.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            success, output = run_command(['sudo', 'cp', sources_path, backup_path])
            if not success:
                return False, f"Yedek dosya oluşturulurken hata: {output}."

        # Dosyayı doğru formatla yaz
        with open(temp_path, "w") as f:
            f.write(content_to_write)
            if not content_to_write.endswith('\n'):
                f.write('\n')

        # Dosyayı taşı
        success, output = run_command(['sudo', 'mv', temp_path, sources_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}."

        # Depoları güncelle
        print("Depo listesi güncellendi, 'apt-get update' çalıştırılıyor...")
        success, output = run_command(['sudo', 'apt-get', 'update'], timeout=120)
        if not success:
            return False, f"'apt-get update' çalıştırılırken hata: {output}."

        return True, "Paket yöneticisi depoları başarıyla standart yapılandırmaya getirildi."

    except Exception as e:
        return False, f"APT depoları uygulanırken genel hata: {e}"

# ==============================================================================
# == GPG ANAHTAR VE GÜNCELLEME POLİTİKALARI =====================================
# ==============================================================================
def audit_gpg_keys(username, parameters):
    """
    Sistemdeki tüm APT GPG anahtarlarının parmak izlerini, parametre olarak verilen 
    onaylı parmak izi listesiyle karşılaştırır. Hem yetkisiz hem de eksik anahtarları raporlar.
    Bu politika, otomatik düzeltme (apply) yapmaz, sadece denetler.
    """
    # 1. Sunucudan gelen parametreyi akıllıca işle
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
    
    # 2. Sistemdeki tüm anahtar konumlarını tara
    keyring_paths = ["/etc/apt/keyrings", "/usr/share/keyrings", "/etc/apt/trusted.gpg.d"]
    found_fingerprints = set()
    
    try:
        for path in keyring_paths:
            if os.path.isdir(path):
                for filename in os.listdir(path):
                    if filename.endswith((".gpg", ".asc")):
                        key_file = os.path.join(path, filename)
                        gpg_cmd = ['gpg', '--batch', '--no-tty', '--with-colons', '--with-fingerprint', key_file]
                        success, output = run_command(gpg_cmd)

                        if not success:
                            continue 

                        for line in output.splitlines():
                            if line.startswith("fpr"):
                                fingerprint = line.strip().split(':')[9]
                                if fingerprint:
                                    found_fingerprints.add(fingerprint)

        if not found_fingerprints:
            return False, "Sistemde taranan dizinlerde hiçbir geçerli GPG anahtarı bulunamadı."

        # 3. Bulunan ve izin verilen listeleri karşılaştır
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
# == PARDUS İÇİN OTOMATİK GÜNCELLEME POLİTİKASI (CRON TABANLI) ===================
# ==============================================================================

def enable_pardus_automatic_updates(username, parameters):
    """
    Pardus sistemlerde günlük otomatik güncellemeleri etkinleştirmek için
    /etc/cron.daily dizinine bir güncelleme betiği oluşturur.
    """
    # Bu politika parametre gerektirmez.
    cron_script_path = "/etc/cron.daily/pmys-automatic-updates"
    
    try:
        # cron betiğinin var olup olmadığını kontrol et
        if os.path.exists(cron_script_path):
            # Dosyanın varlığı, politikanın zaten uygulandığını gösterir.
            return True, "Otomatik güncelleme betiği zaten mevcut."
        else:
            return apply_pardus_automatic_updates()

    except Exception as e:
        return False, f"Pardus otomatik güncelleme kontrolünde hata: {e}"

def apply_pardus_automatic_updates():
    """
    Günlük güncellemeleri yapacak olan betiği oluşturur ve çalıştırılabilir yapar.
    """
    cron_script_path = "/etc/cron.daily/pmys-automatic-updates"
    temp_path = "/tmp/pmys-automatic-updates.sh"
    
    # Oluşturulacak betiğin (script) içeriği
    script_content = """#!/bin/bash
# PMYS Agent tarafından Pardus için otomatik güncelleme amacıyla oluşturulmuştur.
# Bu betik /etc/cron.daily dizininde bulunduğu için sistem tarafından her gün otomatik çalıştırılır.

# Paket listesini yeniler ve tüm güncellemeleri `-y` parametresiyle
# otomatik onaylayarak yükler. Ardından gereksiz paketleri temizler.
apt-get update && apt-get upgrade -y && apt-get autoremove -y

exit 0
"""

    try:
        # 1. Betiği önce geçici bir dosyaya yaz
        with open(temp_path, "w") as f:
            f.write(script_content)

        # 2. Geçici dosyayı sudo ile asıl yerine taşı
        success, output = run_command(['sudo', 'mv', temp_path, cron_script_path])
        if not success:
            return False, f"Geçici dosya taşınırken hata: {output}. 'sudoers' dosyasını kontrol edin."

        # 3. Betiği çalıştırılabilir yap (chmod +x)
        success, output = run_command(['sudo', 'chmod', '+x', cron_script_path])
        if not success:
            return False, f"Betik çalıştırılabilir hale getirilirken hata: {output}. 'sudoers' dosyasını kontrol edin."

        return True, "Günlük otomatik güncelleme betiği başarıyla oluşturuldu."
  
    except Exception as e:
        return False, f"Güncelleme betiği uygulanırken genel hata: {e}"