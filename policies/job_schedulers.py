###############################################################################################################################
###                                                                                                                         ###
###                                             CIS JOB SCHEDULERS GÜVENLİK AYARLARI                                        ###
###                                                                                                                         ###
###############################################################################################################################


import os
import stat


from utils import run_command
from logger import logger



def check_cron_service_policy():
    """
    CIS 2.4.1.1: Ensure cron daemon is enabled and active
    Bu fonksiyon cron (veya crond) servisinin aktif ve enable durumda olup olmadığını kontrol eder.
    """
    try:
        success, output = run_command(["systemctl", "list-unit-files"])
        if not success:
            return False, f"Servis listesi alınamadı: {output}"

        service_name = None
        for line in output.splitlines():
            if line.startswith("cron.service") or line.startswith("crond.service"):
                service_name = line.split()[0]
                break

        if not service_name:
            return True, "Cron servisi sistemde kurulu değil, politika uygulanabilir değil."

        success, enabled_status = run_command(["systemctl", "is-enabled", service_name])
        if not success:
            return False, f"{service_name} enable durumu okunamadı: {enabled_status}"

        success, active_status = run_command(["systemctl", "is-active", service_name])
        if not success:
            return False, f"{service_name} active durumu okunamadı: {active_status}"

        enabled_status = enabled_status.strip()
        active_status = active_status.strip()

        if enabled_status == "enabled" and active_status == "active":
            return True, f"{service_name} aktif ve enable durumda."
        else:
            return False, f"{service_name} aktif değil veya enable değil. (enabled={enabled_status}, active={active_status})"

    except Exception as e:
        return False, f"Cron servisi kontrol hatası: {str(e)}"


def apply_cron_service_policy(username=None, param=None):
    """
    CIS 2.4.1.1: Ensure cron daemon is enabled and active
    Bu fonksiyon cron (veya crond) servisinin aktif ve enable durumda olmasını sağlar.
    Gerekirse düzeltme yapar.
    """
    try:

        status, message = check_cron_service_policy()
        if status:
            return True, message

        # Hangi servis kullanılıyor
        success, output = run_command(["systemctl", "list-unit-files"])
        if not success:
            logger.error(f"[Servis listesi alınamadı: {output}]")
            return False, f"Servis listesi alınamadı: {output}"

        service_name = None
        for line in output.splitlines():
            if line.startswith("cron.service") or line.startswith("crond.service"):
                service_name = line.split()[0]
                break

        if not service_name:
            logger.error("[Cron servisi sistemde kurulu değil, politika uygulanabilir değil.]")
            return False, "Cron servisi sistemde kurulu değil, politika uygulanabilir değil."

        run_command(["systemctl", "unmask", service_name])
        run_command(["systemctl", "--now", "enable", service_name])

        status, message = check_cron_service_policy()
        if status:
            logger.info(f"[{service_name} servisi aktif hale getirildi ve enable yapıldı.]")
            return True, f"{service_name} servisi aktif hale getirildi ve enable yapıldı."
        else:
            logger.error(f"[{service_name} düzeltme sonrası da uygun değil: {message}]")
            return False, f"{service_name} düzeltme sonrası da uygun değil: {message}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[2.4.1.1][APPLY] {msg}")
        return False, f"cron servisi uygulama hatası: {msg}"



def check_crontab_file_authorities():
    """
    CIS 2.4.1.2: Ensure permissions on /etc/crontab are configured.
    Beklenen:
      - Owner: root
      - Group: root
      - Permissions: 600
    """
    try:
        expected_perms = "600"
        expected_uid = "0"
        expected_gid = "0"

        success, output = run_command([
            "stat", "-Lc", "%a %u %g", "/etc/crontab"
        ])
        if not success:
            return False, f"/etc/crontab bilgisi alınamadı: {output}"

        parts = output.strip().split()
        if len(parts) != 3:
            return False, f"Beklenmeyen stat komut çıktısı: {output}"

        perms, uid, gid = parts
        if perms == expected_perms and uid == expected_uid and gid == expected_gid:
            return True, f"/etc/crontab doğru (perms={perms}, uid={uid}, gid={gid})."
        else:
            return False, (
                f"/etc/crontab hatalı: perms={perms}, uid={uid}, gid={gid} "
                f"(beklenen perms={expected_perms}, uid={expected_uid}, gid={expected_gid})."
            )

    except Exception as e:
        return False, f"/etc/crontab kontrol hatası: {str(e)}"


def apply_crontab_file_authorities(username=None, param=None):
    """
    CIS 2.4.1.2: Ensure permissions on /etc/crontab are configured.
    """
    try:
        check_ok, check_msg = check_crontab_file_authorities()
        if check_ok:
            logger.info("[/etc/crontab] Zaten uyumlu: " + check_msg)
            return True, check_msg

        expected_perms = "600"

        run_command(["chown", "root:root", "/etc/crontab"])

        run_command(["chmod", expected_perms, "/etc/crontab"])

        check_ok, check_msg = check_crontab_file_authorities()
        if check_ok:
            logger.info("[/etc/crontab] Düzeltildi: " + check_msg)
            return True, f"/etc/crontab düzeltildi: {check_msg}"
        else:
            logger.error("[/etc/crontab] Düzeltme sonrası da hatalı: " + check_msg)
            return False, f"/etc/crontab düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.2][APPLY] {msg}")
        return False, f"/etc/crontab izin düzeltme hatası: {msg}"


def check_cron_hourly_permissions():
    """
    CIS 2.4.1.3: Ensure permissions on /etc/cron.hourly are configured
    Beklenen:
      - Owner: root
      - Group: root
      - Permissions: 700
    """
    try:
        expected_perms = "700"
        expected_owner = "0"  # root UID
        expected_group = "0"  # root GID

        success, output = run_command([
            "stat", "-Lc", "%a %u %g", "/etc/cron.hourly"
        ])
        if not success:
            return False, f"/etc/cron.hourly bilgisi alınamadı: {output}"

        parts = output.strip().split()
        if len(parts) != 3:
            return False, f"Beklenmeyen stat çıktısı: {output}"

        perms, uid, gid = parts
        if perms == expected_perms and uid == expected_owner and gid == expected_group:
            return True, f"/etc/cron.hourly izinleri doğru ({perms}, uid={uid}, gid={gid})."
        else:
            return False, f"/etc/cron.hourly hatalı: perms={perms}, uid={uid}, gid={gid} (beklenen perms={expected_perms}, uid={expected_owner}, gid={expected_group})."

    except Exception as e:
        return False, f"/etc/cron.hourly kontrol hatası: {str(e)}"


def apply_cron_hourly_permissions(username=None, param=None):
    """
    CIS 2.4.1.3: Ensure permissions on /etc/cron.hourly are configured
    """
    try:
        check_ok, check_msg = check_cron_hourly_permissions()
        if check_ok:
            logger.info("[/etc/cron.hourly] Zaten uyumlu: " + check_msg)
            return True, check_msg

        run_command(["chown", "root:root", "/etc/cron.hourly"])
        run_command(["chmod", "700", "/etc/cron.hourly"])

        check_ok, check_msg = check_cron_hourly_permissions()
        if check_ok:
            logger.info("[/etc/cron.hourly] Düzeltildi: " + check_msg)
            return True, f"/etc/cron.hourly izinleri düzeltildi. {check_msg}"
        else:
            logger.error("[/etc/cron.hourly] Düzeltme sonrası da hatalı: " + check_msg)
            return False, f"/etc/cron.hourly düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.3][APPLY] {msg}")
        return False, f"/etc/cron.hourly izin düzeltme hatası: {msg}"



def check_cron_daily_authorities():
    """
    CIS 2.4.1.4: Ensure permissions on /etc/cron.daily are configured.
    Beklenen:
      - Owner: root
      - Group: root
      - Permissions: 700
    """
    try:
        expected_perms = "700"
        expected_uid = "0"
        expected_gid = "0"

        success, output = run_command([
            "stat", "-Lc", "%a %u %g", "/etc/cron.daily"
        ])
        if not success:
            return False, f"/etc/cron.daily bilgisi alınamadı: {output}"

        parts = output.strip().split()
        if len(parts) != 3:
            return False, f"Beklenmeyen stat çıktısı: {output}"

        perms, uid, gid = parts
        if perms == expected_perms and uid == expected_uid and gid == expected_gid:
            return True, f"/etc/cron.daily doğru (perms={perms}, uid={uid}, gid={gid})."
        else:
            return False, (
                f"/etc/cron.daily hatalı: perms={perms}, uid={uid}, gid={gid} "
                f"(beklenen perms={expected_perms}, uid={expected_uid}, gid={expected_gid})."
            )

    except Exception as e:
        return False, f"/etc/cron.daily kontrol hatası: {str(e)}"


def apply_cron_daily_authorities(username=None, param=None):
    """
    CIS 2.4.1.4: Ensure permissions on /etc/cron.daily are configured.
    """
    try:
        check_ok, check_msg = check_cron_daily_authorities()
        if check_ok:
            logger.info("[/etc/cron.daily] Zaten uyumlu: " + check_msg)
            return True, check_msg

        expected_perms = "700"

        run_command(["chown", "root:root", "/etc/cron.daily"])
        run_command(["chmod", expected_perms, "/etc/cron.daily"])

        check_ok, check_msg = check_cron_daily_authorities()
        if check_ok:
            logger.info("[/etc/cron.daily] Düzeltildi: " + check_msg)
            return True, f"/etc/cron.daily düzeltildi: {check_msg}"
        else:
            logger.error("[/etc/cron.daily] Düzeltme sonrası da hatalı: " + check_msg)
            return False, f"/etc/cron.daily düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.4][APPLY] {msg}")
        return False, f"/etc/cron.daily izin düzeltme hatası: {msg}"



def check_cron_weekly_permissions():
    """
    CIS 2.4.1.5: Ensure permissions on /etc/cron.weekly are configured.
    Beklenen: root:root sahiplik, 700 izinler.
    """
    try:
        success, output = run_command(
            ["stat", "-Lc", "Access: (%a) Uid: (%u) Gid: (%g)", "/etc/cron.weekly/"]
        )
        if not success:
            return False, f"/etc/cron.weekly kontrol edilemedi: {output}"

        parts = output.replace("Access:", "").replace("Uid:", "").replace("Gid:", "").split()
        perms, uid, gid = parts[0].strip("()"), parts[1].strip("()"), parts[2].strip("()")

        if perms == "700" and uid == "0" and gid == "0":
            return True, "/etc/cron.weekly izinleri doğru (700, root:root)."
        else:
            return False, f"/etc/cron.weekly izinleri yanlış (perms={perms}, uid={uid}, gid={gid}), beklenen 700 ve root:root."

    except Exception as e:
        return False, f"/etc/cron.weekly kontrol hatası: {str(e)}"


def apply_cron_weekly_permissions(username=None, param=None):
    """
    CIS 2.4.1.5: Ensure permissions on /etc/cron.weekly are configured.
    """
    try:
        check_ok, check_msg = check_cron_weekly_permissions()
        if check_ok:
            return True, check_msg

        expected_perms = "700"

        run_command(["chown", "root:root", "/etc/cron.weekly/"])
        run_command(["chmod", expected_perms, "/etc/cron.weekly/"])

        check_ok, check_msg = check_cron_weekly_permissions()
        if check_ok:
            return True, f"/etc/cron.weekly izinleri 700 ve root:root olarak ayarlandı: {check_msg}"
        else:
            return False, f"/etc/cron.weekly düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.5][APPLY] {msg}")
        return False, f"/etc/cron.weekly izin düzeltme hatası: {msg}"



def check_cron_monthly_permissions():
    """
    CIS 2.4.1.6: Ensure permissions on /etc/cron.monthly are configured.
    Beklenen: root:root sahiplik, 700 izinler.
    """
    try:
        success, output = run_command(
            ["stat", "-Lc", "Access: (%a/%A) Uid: (%u/%U) Gid: (%g/%G)", "/etc/cron.monthly/"]
        )
        if not success:
            return False, f"/etc/cron.monthly kontrol edilemedi: {output}"

        parts = output.split()
        perms = parts[1].split("/")[0].strip("()")
        uid = parts[3].split("/")[0].strip("()")
        gid = parts[5].split("/")[0].strip("()")

        if perms == "700" and uid == "0" and gid == "0":
            return True, "/etc/cron.monthly izinleri doğru (700, root:root)."
        else:
            return False, f"/etc/cron.monthly izinleri yanlış (perms={perms}, uid={uid}, gid={gid}), beklenen 700 ve root:root."

    except Exception as e:
        return False, f"/etc/cron.monthly kontrol hatası: {str(e)}"


def apply_cron_monthly_permissions(username=None, param=None):
    """
    CIS 2.4.1.6: Ensure permissions on /etc/cron.monthly are configured.
    """
    try:
        check_ok, check_msg = check_cron_monthly_permissions()
        if check_ok:
            return True, check_msg

        run_command(["chown", "root:root", "/etc/cron.monthly/"])
        run_command(["chmod", "700", "/etc/cron.monthly/"])

        check_ok, check_msg = check_cron_monthly_permissions()
        if check_ok:
            return True, f"/etc/cron.monthly izinleri düzeltildi: {check_msg}"
        else:
            return False, f"/etc/cron.monthly düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.6][APPLY] {msg}")
        return False, f"/etc/cron.monthly izin düzeltme hatası: {msg}"



def check_cron_d_permissions():
    """
    CIS 2.4.1.7: Ensure permissions on /etc/cron.d are configured.
    Beklenen: root:root sahiplik, 700 izinler.
    """
    try:
        success, output = run_command(
            ["stat", "-Lc", "%a %u %g", "/etc/cron.d/"]
        )
        if not success:
            return False, f"/etc/cron.d kontrol edilemedi: {output}"

        perms, uid, gid = output.strip().split()
        if perms == "700" and uid == "0" and gid == "0":
            return True, "cron.d izinleri UID 0 hesabına ait (uygun)."
        else:
            return False, f"/etc/cron.d izinleri hatalı: perms={perms}, uid={uid}, gid={gid}"
    except Exception as e:
        return False, f"/etc/cron.d kontrol hatası: {str(e)}"


def apply_cron_d_permissions(username=None, param=None):
    """
    CIS 2.4.1.7: Ensure permissions on /etc/cron.d are configured.
    """
    try:
        check_ok, check_msg = check_cron_d_permissions()
        if check_ok:
            return True, check_msg

        run_command(["chown", "root:root", "/etc/cron.d/"])
        run_command(["chmod", "700", "/etc/cron.d/"])

        check_ok, check_msg = check_cron_d_permissions()
        if check_ok:
            return True, f"/etc/cron.d izinleri düzeltildi: {check_msg}"
        else:
            return False, f"/etc/cron.d düzeltme sonrası da hatalı: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.7] [APPLY] {msg}")
        return False, f"/etc/cron.d izin düzeltme hatası: {msg}"




def check_crontab_restriction():
    """
    CIS 2.4.1.8: Ensure crontab is restricted to authorized users.
    """
    try:
        
        if os.path.exists("/etc/cron.allow"):
            success, output = run_command(
                ["stat", "-Lc", "Access: (%a) Owner: (%U) Group: (%G)", "/etc/cron.allow"]
            )
            if not success:
                return False, f"/etc/cron.allow kontrol edilemedi: {output}"

            parts = output.replace("Access:", "").replace("Owner:", "").replace("Group:", "").split()
            perms, owner, group = parts[0].strip("()"), parts[1].strip("()"), parts[2].strip("()")

            if int(perms) > 640:
                return False, f"/etc/cron.allow izinleri çok gevşek ({perms}), beklenen 640 veya daha kısıtlı."
            if owner != "root":
                return False, f"/etc/cron.allow owner {owner}, beklenen root."
            if group not in ("root", "crontab"):
                return False, f"/etc/cron.allow group {group}, beklenen root veya crontab."
            return True, "/etc/cron.allow doğru yapılandırılmış."

        # Eğer cron.allow yoksa, cron.deny kontrol edilir
        elif os.path.exists("/etc/cron.deny"):
            success, output = run_command(
                ["stat", "-Lc", "Access: (%a) Owner: (%U) Group: (%G)", "/etc/cron.deny"]
            )
            if not success:
                return False, f"/etc/cron.deny kontrol edilemedi: {output}"

            parts = output.replace("Access:", "").replace("Owner:", "").replace("Group:", "").split()
            perms, owner, group = parts[0].strip("()"), parts[1].strip("()"), parts[2].strip("()")

            if int(perms, 8) > int("640", 8):
                return False, f"/etc/cron.deny izinleri çok gevşek ({perms}), beklenen 640 veya daha kısıtlı."
            if owner != "root":
                return False, f"/etc/cron.deny owner {owner}, beklenen root."
            if group not in ("root", "crontab"):
                return False, f"/etc/cron.deny group {group}, beklenen root veya crontab."
            return True, "/etc/cron.deny doğru yapılandırılmış."

        else:
            
            return False, "Ne /etc/cron.allow ne de /etc/cron.deny mevcut."

    except Exception as e:
        return False, f"crontab kısıtlama kontrol hatası: {str(e)}"


def apply_crontab_restriction(username=None, param=None):
    """
    CIS 2.4.1.8: Ensure crontab is restricted to authorized users.
    """
    try:
        if not os.path.exists("/etc/cron.allow"):
            run_command(["touch", "/etc/cron.allow"])

        success, _ = run_command(["getent", "group", "crontab"])
        group = "crontab" if success else "root"

        run_command(["chown", f"root:{group}", "/etc/cron.allow"])
        run_command(["chmod", "640", "/etc/cron.allow"]) 

        if username:
            with open("/etc/cron.allow", "r+") as f:
                lines = [line.strip() for line in f.readlines()]
                if username not in lines:
                    f.write(f"{username}\n")

        if os.path.exists("/etc/cron.deny"):
            run_command(["chown", f"root:{group}", "/etc/cron.deny"])
            run_command(["chmod", "640", "/etc/cron.deny"])

        check_ok, check_msg = check_crontab_restriction()
        if check_ok:
            logger.info(f"[CIS 2.4.1.8] crontab kısıtlamaları uygulandı: {check_msg}")
            return True, f"crontab kısıtlamaları uygulandı: {check_msg}"
        else:
            logger.error(f"[CIS 2.4.1.8] crontab kısıtlamaları düzeltilemedi: {check_msg}")
            return False, f"crontab kısıtlamaları düzeltilemedi: {check_msg}"

    except Exception as e:
        msg = f"Hata: {str(e)}"
        logger.error(f"[CIS 2.4.1.8][APPLY] {msg}")
        return False, f"crontab kısıtlama düzeltme hatası: {msg}"