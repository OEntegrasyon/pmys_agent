import os
import shutil
import subprocess
import time
from datetime import datetime
from utils import get_logged_in_user, get_desktop_env, run_command
from logger import logger

# ==============================================================================
# == GÜVENLİK DUVARI (FIREWALL) POLİTİKASI ======================================
# ==============================================================================

### CIS : Host-Based Firewall Yapılandırması ###

def configure_secure_firewall(username, parameters):
    """
    UFW güvenlik duvarını kontrol eder ve parametrelerdeki kurallarla eşleşmiyorsa düzeltir.
    """
    rules_string = parameters.get("allowed_rules", "")
    if not rules_string:
        return False, "Politika hatası: 'allowed_rules' parametresi belirtilmemiş."

    # DÜZELTME: Gelen string'i ';' karakterinden bölerek bir listeye çeviriyoruz.
    allowed_rules = [rule.strip() for rule in rules_string.split(';') if rule.strip()]
    if not allowed_rules:
        return False, "Politika hatası: 'allowed_rules' parametresi boş."

    try:
        success, output = run_command(['sudo', 'ufw', 'status'])
        if not success or "Status: inactive" in output:
            return apply_secure_firewall(parameters)

        # Mevcut kuralları kontrol et
        all_rules_exist = True
        for rule in allowed_rules:
            rule_check_part = rule.split()[-1] # 'allow 22/tcp' -> '22/tcp'
            if rule_check_part not in output:
                all_rules_exist = False
                break
        
        if all_rules_exist:
            return True, "Güvenlik duvarı (UFW) zaten istenen yapılandırmada."
        else:
            return apply_secure_firewall(parameters)
    except Exception as e:
        return False, f"Güvenlik duvarı kontrolünde hata: {e}"


def apply_secure_firewall(parameters):
    """
    UFW'yi yapılandırır ve parametrelerdeki kuralları uygular.
    """
    rules_string = parameters.get("allowed_rules", "")
    if not rules_string:
        return False, "Parametrelerde 'allowed_rules' listesi boş."

    # DÜZELTME: Gelen string'i ';' karakterinden bölerek bir listeye çeviriyoruz.
    allowed_rules = [rule.strip() for rule in rules_string.split(';') if rule.strip()]
    if not allowed_rules:
        return False, "Parametrelerde 'allowed_rules' listesi boş."

    # Adım 1: Kurulum, sıfırlama ve varsayılanları ayarlama
    run_command(['sudo', 'apt-get', 'install', '-y', 'ufw'])
    run_command(['sudo', 'ufw', '--force', 'reset'])
    run_command(['sudo', 'ufw', 'default', 'deny', 'incoming'])
    run_command(['sudo', 'ufw', 'default', 'allow', 'outgoing'])

    # Adım 2: Listedeki tüm kuralları uygula
    for rule_string in allowed_rules:
        rule_parts = rule_string.split()
        if not rule_parts: continue
        logger.info(f"UFW kuralı uygulanıyor: '{rule_string}'")
        success, output = run_command(['sudo', 'ufw'] + rule_parts)
        if not success:
            return False, f"UFW kuralı '{rule_string}' uygulanırken hata: {output}"
    
    # Adım 3: UFW'yi etkinleştir
    logger.info("UFW etkinleştiriliyor...")
    success, output = run_command(['sudo', 'ufw', '--force', 'enable'])
    if not success:
        return False, f"UFW etkinleştirilirken hata: {output}"
    
    return True, f"Güvenlik duvarı (UFW) başarıyla etkinleştirildi ve {len(allowed_rules)} kural uygulandı."

# ------------------------------------------------------------------------------

