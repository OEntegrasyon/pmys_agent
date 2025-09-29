from configparser import ConfigParser
import threading, pika, json, os
import random, string, time
from logger import logger
from utils import (
    get_logged_in_user, 
    login_notify, 
    first_time_register,
    get_connection_parameters,
    send_response
    )
import policies
import default_policy

current_logged_in_user = None

def login_detection(conn_params, uuid):
    last_user = None
    while True:
        temp_user = get_logged_in_user()
        if temp_user is not None and temp_user != last_user:
            current_logged_in_user = temp_user
            logger.info(f"Yeni kullanıcı algılandı: {current_logged_in_user}")

            # revert_all_policies()
            
            login_notify(current_logged_in_user, conn_params, uuid)
            last_user = temp_user
        elif temp_user is None and last_user is not None:
            current_logged_in_user = None
            last_user = None
            logger.info("Kullanıcı çıkış yaptı veya algılanamıyor.")

        time.sleep(3)

def on_policy_received(channel, method, properties, body):
    user = get_logged_in_user()
    data = json.loads(body)
    
    # DÜZELTME: Mesaj işlendikten sonra her durumda onay gönderilmesi için
    # basic_ack'i döngüden sonra ve en sona taşıyoruz.
    try:
        username = data.get("username", "unknown")
        if username == user:
            for policy in data.get("policies", []):
                policy_type = policy.get("policy_type__name", "unknown")
                policy_parameters = policy.get("parameters", {})
                logger.info(f"[on_policy_received] Politika alındı: {policy_type} for {username}, Parametreler: {policy_parameters}")
                
                success, result_msg = apply_policy(username, policy_type, policy_parameters)
                
                action = "policy_applied" if success else "policy_failed"
                details = {"username": user, "policy_type": policy_type, "parameters": policy_parameters, "message": result_msg}
                send_response(action, details)
                if not success:
                    logger.error(f"[on_policy_received] Politika uygulanamadı: {policy_type} for {username}, Hata: {result_msg}")
    
    finally:
        # Bu blok, yukarıda bir hata olsa bile çalışır.
        # Bu sayede bozuk mesajlar bile işlenmiş kabul edilir ve kuyruktan silinir.
        channel.basic_ack(delivery_tag=method.delivery_tag)

def apply_policy(username, policy_type, parameters):
    policy_function = getattr(policies, policy_type, None)
    
    # DÜZELTME: Fonksiyonu çağırmadan önce var olup olmadığını kontrol et.
    if policy_function is None:
        error_msg = f"Tanımsız veya bulunamayan politika tipi: '{policy_type}'"
        logger.error(f"[apply_policy] {error_msg}")
        return False, error_msg

    logger.info(f"[apply_policy] Politika tipi: {policy_type}, Parametreler: {json.dumps(parameters)}")
    # Hata kontrolü, her bir politika fonksiyonunun kendi içine (try/except) eklenmeli.
    try:
        return policy_function(username, parameters)
    except Exception as e:
        error_msg = f"'{policy_type}' politikası uygulanırken hata oluştu: {str(e)}"
        logger.error(f"[apply_policy] {error_msg}")
        return False, error_msg
def listen_for_policies(conn_params):
    try:
        connection = pika.BlockingConnection(conn_params)
        channel = connection.channel()
        channel.queue_declare(queue='user_policy_queue', durable=True)
        
        channel.basic_consume(queue='user_policy_queue', 
                                on_message_callback=on_policy_received, 
                                auto_ack=False)
        channel.start_consuming()
    except Exception as e:
        logger.error(f"[listen_for_policies] Hata: {str(e)}")

def main():
    default_policy.restore_all_to_default()
    uuid, conn_params, config, config_file = get_connection_parameters()

    if not uuid:
        uuid = first_time_register(conn_params)
        if not uuid:
            logger.error("UUID alınamadı, program sonlandırılıyor.")
            return
        config.set('agent', 'uuid', uuid)
        with open(config_file, 'w') as f:
            config.write(f)
        logger.info(f"İstemci kaydı tamamlandı.")

    login_detection_thread = threading.Thread(target=login_detection, kwargs={'conn_params': conn_params, 'uuid':uuid}, daemon=True)
    listen_for_policies_thread = threading.Thread(target=listen_for_policies, kwargs={'conn_params': conn_params,}, daemon=True)
    login_detection_thread.start()
    listen_for_policies_thread.start()
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()