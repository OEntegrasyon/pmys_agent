import subprocess, psutil, random, string
import pika, json, os
import uuid as uuidlib
from logger import logger
from configparser import ConfigParser
import sys

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(__file__)

def get_connection_parameters():
    config = ConfigParser()
    base_path = get_base_path()
    config_file = os.path.join(base_path, 'agent.conf')
    config.read(config_file)

    connection_name = f"agent-{''.join(random.choices(string.ascii_letters + string.digits, k=10))}"
    uuid = config.get('agent', 'uuid')
    mq_host = config.get('agent', 'mq_host')
    mq_port = config.getint('agent', 'mq_port')
    mq_user = config.get('agent', 'mq_user')
    mq_pass = config.get('agent', 'mq_pass')

    conn_params = pika.ConnectionParameters(
        host=mq_host,
        port=mq_port,
        credentials=pika.PlainCredentials(mq_user, mq_pass),
        client_properties={'connection_name': connection_name},
        heartbeat=60
    )
    return uuid, conn_params, config, config_file
def get_ip_address():
    result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, check=True)
    ip_address = result.stdout.strip().split()[0]
    return ip_address if ip_address else None

def get_mac_by_ip(target_ip):
    for interface_name, interface_addrs in psutil.net_if_addrs().items():
        ip = None
        mac = None
        for addr in interface_addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
            elif addr.family.name == 'AF_PACKET':
                mac = addr.address
        if ip == target_ip:
            return mac
    return None

def get_hostname():
    return subprocess.check_output(['hostname'], text=True).strip()

def get_desktop_env():
    try:
        output = subprocess.check_output("ps -e", text=True).lower()

        if "xfce4-session" in output or "xfwm4" in output:
            return "xfce"
        elif "gnome-session" in output or "gnome-shell" in output:
            return "gnome"
        elif "ksmserver" in output or "plasma" in output:
            return "kde"
        elif "mate-session" in output:
            return "mate"
        elif "lxsession" in output:
            return "lxde"
        else:
            return "bilinmiyor"
    except Exception as e:
        return "bilinmiyor"

def get_logged_in_user(detailed=None):
    try:
        output = subprocess.check_output("loginctl list-sessions --no-legend", shell=True).decode().strip()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4: 
                session_id, uid, user, seat = parts[0], parts[1], parts[2], parts[3]

                is_active = subprocess.check_output(
                    ["loginctl", "show-session", str(session_id), "-p", "Active", "--value"],
                    text=True
                ).strip()

                if is_active == "yes" and user not in ["root", "lightdm", "sddm"] and seat != "-":
                    
                    if detailed:
                        display = subprocess.check_output(
                            ["loginctl", "show-session", str(session_id), "-p", "Display", "--value"],
                            text=True
                        ).strip()
                        dbus = f"unix:path=/run/user/{uid}/bus"
                        return (uid, user, display, dbus)
                    else:
                        return user
              
    except Exception as e:
        logger.error(f"[get_logged_in_user] Hata: {str(e)}")
    
    return None if not detailed else (None, None, None, None)

def login_notify(user, conn_params, uuid):
    try:
        message = {
            "uuid": uuid,
            "hostname": get_hostname(),
            "ip_address": get_ip_address(),
            "mac_address": get_mac_by_ip(get_ip_address()),
            "username": user
        }
        logger.info(f"Giriş yapan kullanıcı: {user}")
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()

        channel.basic_publish(
            exchange='',
            routing_key='client_status',
            body=json.dumps(message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()

    except Exception as e:
        logger.error(f"[login_notify] Hata: {str(e)}")

def first_time_register(conn_params):
    try:
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()

        result = channel.queue_declare(queue='', exclusive=True)
        callback_queue = result.method.queue
        correlation_id = str(uuidlib.uuid4())
        response = None

        def on_response(ch, method, props, body):
            nonlocal response
            if props.correlation_id == correlation_id:
                response = json.loads(body)

        channel.basic_consume(
            queue=callback_queue,
            on_message_callback=on_response,
            auto_ack=True
        )
        message = {
            "uuid": None,
            "hostname": get_hostname(),
            "ip_address": get_ip_address(),
            "mac_address": get_mac_by_ip(get_ip_address()),
            "username": None
        }

        channel.basic_publish(
            exchange='',
            routing_key='client_status',
            body=json.dumps(message),
            properties=pika.BasicProperties(
                reply_to=callback_queue,
                correlation_id=correlation_id,
                delivery_mode=2
            )
        )
        while response is None:
            connection.process_data_events()

        connection.close()

        return response.get("uuid")

    except Exception as e:
        logger.error(f"[first_time_register] Hata: {str(e)}")
        return None

def send_response(action, details):
    response = {"action": action, "details": details}
    logger.info(f"[send_response] Gönderilen mesaj: {json.dumps(response)}")
    uuid, conn_params, config, config_file = get_connection_parameters()
    connection = pika.BlockingConnection(conn_params)
    channel = connection.channel()

    channel.basic_publish(
        exchange='',
        routing_key='client_policy_log',
        body=json.dumps(response),
        properties=pika.BasicProperties(delivery_mode=2)
    )
    connection.close()


    
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