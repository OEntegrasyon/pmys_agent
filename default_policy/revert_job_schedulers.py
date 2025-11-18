###############################################################################################################################
###                                                                                                                         ###
###                                             CIS JOB SCHEDULERS REVERT   AYARLARI                                        ###
###                                                                                                                         ###
###############################################################################################################################

import os
import stat

from logger import logger
from utils import run_command


from policies.job_schedulers import (
    check_cron_hourly_permissions)



def revert_cron_service_policy():
    """
    CIS 2.4.1.1: Revert - Ensure cron daemon is enabled and active
    Bu fonksiyon cron (veya crond) servisinin aktifliğini geri alır (stop + disable + mask).
    """
    try:
        # Cron servis adını tespit etme
        success, output = run_command(["systemctl", "list-unit-files"])
        if not success:
            logger.error(f"[2.4.1.1][REVERT] Servis listesi alınamadı: {output}")
            return False, f"Servis listesi alınamadı: {output}"

        service_name = None
        for line in output.splitlines():
            if line.startswith("cron.service") or line.startswith("crond.service"):
                service_name = line.split()[0]
                break

        if not service_name:
            logger.info("[2.4.1.1][REVERT] Cron servisi sistemde kurulu değil, revert gereksiz.")
            return True, "Cron servisi sistemde kurulu değil, revert gerekli değil."

        # Servisi kapat ve disable + mask
        run_command(["systemctl", "stop", service_name])
        run_command(["systemctl", "disable", service_name])
        run_command(["systemctl", "mask", service_name])

        # Durumu kontrol et
        success1, enabled_status = run_command(["systemctl", "is-enabled", service_name])
        success2, active_status = run_command(["systemctl", "is-active", service_name])

        enabled_status = enabled_status.strip().lower()
        active_status = active_status.strip().lower()

        # Kabul edilebilir varyasyonlar
        enabled_ok = any(s in enabled_status for s in ["disabled", "masked", "not-found", "no such file"])
        active_ok = any(s in active_status for s in ["inactive", "dead", "failed", "could not be found"])

        if enabled_ok and active_ok:
            logger.info(f"[2.4.1.1][REVERT] {service_name} başarıyla devre dışı bırakıldı (enabled={enabled_status}, active={active_status})")
            return True, f"{service_name} başarıyla devre dışı bırakıldı."
        else:
            logger.warning(f"[2.4.1.1][REVERT] {service_name} beklenen revert durumunda değil (enabled={enabled_status}, active={active_status})")
            return False, f"{service_name} beklenen revert durumunda değil (enabled={enabled_status}, active={active_status})."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[2.4.1.1][REVERT] {msg}")
        return False, msg


def revert_crontab_file_authorities():
    """
    CIS 2.4.1.2: Revert - Ensure permissions on /etc/crontab are configured.
    Bu fonksiyon /etc/crontab dosyasını varsayılan izinlere döndürür:
      - Owner: root
      - Group: root
      - Permissions: 644
    """
    try:
        if not os.path.exists("/etc/crontab"):
            logger.warning("[2.4.1.2][REVERT] /etc/crontab dosyası bulunamadı, yapılacak işlem yok.")
            return True, "/etc/crontab yok, revert gerekli değil."

        # Varsayılan izinler
        default_perms = "644"

        run_command(["chown", "root:root", "/etc/crontab"])
        run_command(["chmod", default_perms, "/etc/crontab"])

        # Kontrol
        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/crontab"])
        if success:
            perms, uid, gid = output.strip().split()
            if perms == default_perms and uid == "0" and gid == "0":
                logger.info(f"[2.4.1.2][REVERT] /etc/crontab varsayılan duruma alındı (perms={perms}, uid={uid}, gid={gid}).")
                return True, f"/etc/crontab varsayılan duruma alındı."
            else:
                logger.warning(f"[2.4.1.2][REVERT] /etc/crontab beklenen revert durumunda değil: {output}")
                return False, f"/etc/crontab revert sonrası beklenenden farklı: {output}"
        else:
            logger.error(f"[2.4.1.2][REVERT] stat alınamadı: {output}")
            return False, f"/etc/crontab stat alınamadı: {output}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[2.4.1.2][REVERT] {msg}")
        return False, msg



def revert_cron_hourly_permissions():
    """
    CIS 2.4.1.3 Revert:
    /etc/cron.hourly için default izinlere geri döndür.
    Genelde varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 755
    """
    try:
        check_ok, check_msg = check_cron_hourly_permissions()
        if not check_ok:
            logger.info(f"[CIS 2.4.1.3][REVERT] Uyumlu olmadığı tespit edildi: {check_msg}")
        else:
            logger.info("[CIS 2.4.1.3][REVERT] Zaten apply durumunda, revert edilecek.")

        run_command(["chown", "root:root", "/etc/cron.hourly"])
        run_command(["chmod", "755", "/etc/cron.hourly"])

        # Tekrar kontrol et ama revert koşuluna göre
        success, output = run_command([
            "stat", "-Lc", "%a %u %g", "/etc/cron.hourly"
        ])
        if not success:
            logger.error(f"[CIS 2.4.1.3][REVERT] stat alınamadı: {output}")
            return False, f"/etc/cron.hourly revert stat alınamadı: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "755" and uid == "0" and gid == "0":
            logger.info("[CIS 2.4.1.3][REVERT] Başarıyla varsayılana döndürüldü (755, root:root).")
            return True, "/etc/cron.hourly revert başarılı (755, root:root)."
        else:
            logger.warning(f"[CIS 2.4.1.3][REVERT] Beklenen revert durumunda değil: perms={perms}, uid={uid}, gid={gid}")
            return False, f"/etc/cron.hourly revert başarısız: perms={perms}, uid={uid}, gid={gid}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.3][REVERT] {msg}")
        return False, f"/etc/cron.hourly revert hatası: {msg}"



def revert_cron_daily_authorities():
    """
    CIS 2.4.1.4 Revert:
    /etc/cron.daily için default izinlere geri döndür.
    Genelde varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 755
    """
    try:
        logger.info("[CIS 2.4.1.4][REVERT] Geri alma işlemi başlatıldı...")

        # mevcut durumu kaydet
        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.daily"])
        if success:
            logger.debug(f"[CIS 2.4.1.4][REVERT] Mevcut stat: {output.strip()}")
        else:
            logger.warning(f"[CIS 2.4.1.4][REVERT] stat alınamadı: {output}")

        # Revert işlemleri
        run_command(["chown", "root:root", "/etc/cron.daily"])
        run_command(["chmod", "755", "/etc/cron.daily"])

        # Son durum kontrolü
        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.daily"])
        if not success:
            logger.error(f"[CIS 2.4.1.4][REVERT] stat alınamadı: {output}")
            return False, f"/etc/cron.daily revert sonrası stat alınamadı: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "755" and uid == "0" and gid == "0":
            logger.info("[CIS 2.4.1.4][REVERT] Başarıyla revert edildi (755, root:root).")
            return True, "/etc/cron.daily revert başarılı (755, root:root)."
        else:
            logger.warning(f"[CIS 2.4.1.4][REVERT] Beklenen revert durumu sağlanamadı: perms={perms}, uid={uid}, gid={gid}")
            return False, f"/etc/cron.daily revert başarısız: perms={perms}, uid={uid}, gid={gid}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.4][REVERT] {msg}")
        return False, f"/etc/cron.daily revert hatası: {msg}"


def revert_cron_weekly_permissions():
    """
    CIS 2.4.1.5 Revert:
    /etc/cron.weekly için default izinlere geri döndür.
    Varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 755
    """
    try:
        logger.info("[CIS 2.4.1.5][REVERT] Geri alma işlemi başlatıldı...")

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.weekly/"])
        if success:
            logger.debug(f"[CIS 2.4.1.5][REVERT] Mevcut stat: {output.strip()}")
        else:
            logger.warning(f"[CIS 2.4.1.5][REVERT] stat alınamadı: {output}")

        run_command(["chown", "root:root", "/etc/cron.weekly/"])
        run_command(["chmod", "755", "/etc/cron.weekly/"])

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.weekly/"])
        if not success:
            logger.error(f"[CIS 2.4.1.5][REVERT] stat alınamadı: {output}")
            return False, f"/etc/cron.weekly revert sonrası stat alınamadı: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "755" and uid == "0" and gid == "0":
            logger.info("[CIS 2.4.1.5][REVERT] Başarıyla revert edildi (755, root:root).")
            return True, "/etc/cron.weekly revert başarılı (755, root:root)."
        else:
            logger.warning(f"[CIS 2.4.1.5][REVERT] Beklenen revert sağlanamadı: perms={perms}, uid={uid}, gid={gid}")
            return False, f"/etc/cron.weekly revert başarısız: perms={perms}, uid={uid}, gid={gid}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.5][REVERT] {msg}")
        return False, f"/etc/cron.weekly revert hatası: {msg}"



def revert_cron_monthly_permissions():
    """
    CIS 2.4.1.6 Revert:
    /etc/cron.monthly dizin izinlerini varsayılanlara geri döndür.
    Varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 755
    """
    try:
        logger.info("[CIS 2.4.1.6][REVERT] Geri alma işlemi başlatıldı...")

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.monthly/"])
        if success:
            logger.debug(f"[CIS 2.4.1.6][REVERT] Mevcut stat: {output.strip()}")
        else:
            logger.warning(f"[CIS 2.4.1.6][REVERT] stat alınamadı: {output}")

        run_command(["chown", "root:root", "/etc/cron.monthly/"])
        run_command(["chmod", "755", "/etc/cron.monthly/"])

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.monthly/"])
        if not success:
            logger.error(f"[CIS 2.4.1.6][REVERT] stat alınamadı: {output}")
            return False, f"/etc/cron.monthly revert sonrası stat alınamadı: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "755" and uid == "0" and gid == "0":
            logger.info("[CIS 2.4.1.6][REVERT] Başarıyla revert edildi (755, root:root).")
            return True, "/etc/cron.monthly revert başarılı (755, root:root)."
        else:
            logger.warning(f"[CIS 2.4.1.6][REVERT] Beklenen revert sağlanamadı: perms={perms}, uid={uid}, gid={gid}")
            return False, f"/etc/cron.monthly revert başarısız: perms={perms}, uid={uid}, gid={gid}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.6][REVERT] {msg}")
        return False, f"/etc/cron.monthly revert hatası: {msg}"


def revert_cron_d_permissions():
    """
    CIS 2.4.1.7 Revert:
    /etc/cron.d dizin izinlerini varsayılanlara geri döndür.
    Varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 755
    """
    try:
        logger.info("[CIS 2.4.1.7][REVERT] Geri alma işlemi başlatıldı...")

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.d/"])
        if success:
            logger.debug(f"[CIS 2.4.1.7][REVERT] Mevcut stat: {output.strip()}")
        else:
            logger.warning(f"[CIS 2.4.1.7][REVERT] stat alınamadı: {output}")

        run_command(["chown", "root:root", "/etc/cron.d/"])
        run_command(["chmod", "755", "/etc/cron.d/"])

        success, output = run_command(["stat", "-Lc", "%a %u %g", "/etc/cron.d/"])
        if not success:
            logger.error(f"[CIS 2.4.1.7][REVERT] stat alınamadı: {output}")
            return False, f"/etc/cron.d revert sonrası stat alınamadı: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "755" and uid == "0" and gid == "0":
            logger.info("[CIS 2.4.1.7][REVERT] Başarıyla revert edildi (755, root:root).")
            return True, "/etc/cron.d revert başarılı (755, root:root)."
        else:
            logger.warning(f"[CIS 2.4.1.7][REVERT] Beklenen revert sağlanamadı: perms={perms}, uid={uid}, gid={gid}")
            return False, f"/etc/cron.d revert başarısız: perms={perms}, uid={uid}, gid={gid}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.7][REVERT] {msg}")
        return False, f"/etc/cron.d revert hatası: {msg}"



def revert_crontab_restriction():
    """
    CIS 2.4.1.8 Revert:
    /etc/cron.allow ve /etc/cron.deny dosyalarının izinlerini ve sahipliğini
    varsayılan hale geri döndürür.
    Varsayılan:
      - Owner: root
      - Group: root
      - Permissions: 644
      - username satırı geri silinmez, sadece izin/sahiplik geri alınır
    """
    try:
        logger.info("[CIS 2.4.1.8][REVERT] Geri alma işlemi başlatıldı...")

        files = ["/etc/cron.allow", "/etc/cron.deny"]

        for fpath in files:
            if os.path.exists(fpath):
                run_command(["chown", "root:root", fpath])
                run_command(["chmod", "644", fpath])

                success, output = run_command(["stat", "-Lc", "%a %u %g", fpath])
                if success:
                    perms, uid, gid = output.strip().split()
                    if perms == "644" and uid == "0" and gid == "0":
                        logger.info(f"[CIS 2.4.1.8][REVERT] {fpath} varsayılanlara geri alındı (644, root:root).")
                    else:
                        logger.warning(f"[CIS 2.4.1.8][REVERT] {fpath} beklenen revert sağlanamadı: perms={perms}, uid={uid}, gid={gid}")
                else:
                    logger.warning(f"[CIS 2.4.1.8][REVERT] {fpath} stat alınamadı: {output}")
            else:
                logger.info(f"[CIS 2.4.1.8][REVERT] {fpath} mevcut değil, işlem atlandı.")

        return True, "Crontab revert işlemi tamamlandı."

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.8][REVERT] {msg}")
        return False, f"Crontab revert hatası: {msg}"