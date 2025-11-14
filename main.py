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
from laps_worker import LapsWorker

current_logged_in_user = None

def login_detection(conn_params, uuid):
    last_user = None
    while True:
        temp_user = get_logged_in_user()
        
        if temp_user is not None and temp_user != last_user:
            logger.info(f"Yeni kullanıcı girişi algılandı: {temp_user}.")

            login_notify(temp_user, conn_params, uuid)
            last_user = temp_user 

        elif temp_user is None and last_user is not None:
            logger.info(f"Kullanıcı {last_user} oturumu kapattı. CIS politikaları temizleniyor.")
 
            default_policy.restore_all_to_default()
            
            logger.info(f"Sadece istemci bazlı politikaları uygulamak için sunucuya bildiriliyor.")

            login_notify(None, conn_params, uuid) 
            
            last_user = None
 
        time.sleep(3)

def on_policy_received(channel, method, properties, body):
    user = get_logged_in_user()
    data = json.loads(body)

    try:
        username = data.get("username")
        client_uuid = data.get("client_uuid") 

        if username and username != user:
            logger.warning(f"Politika uyuşmazlığı. Beklenen: '{user}', Gelen: '{username}'. Atlanıyor.")
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        policy_data = data.get("policies", {})
        user_policies = policy_data.get("user", [])
        client_policies = policy_data.get("client", [])

        final_policies = {}
        policy_source = {} 

        for policy in user_policies:
            policy_type = policy.get("policy_type__name")
            if policy_type:
                final_policies[policy_type] = policy
                policy_source[policy_type] = "user" 

        for policy in client_policies:
            policy_type = policy.get("policy_type__name")
            if policy_type:
                logger.info(f"İstemci politikası '{policy_type}' öncelik kazanıyor.")
                final_policies[policy_type] = policy
                policy_source[policy_type] = "client" 

        logger.info(f"Uygulanacak {len(final_policies)} adet nihai politika mevcut.")

        for policy_type, policy in final_policies.items(): 
            policy_parameters = policy.get("parameters", {})
            source = policy_source.get(policy_type, "unknown") 

            logger.info(f"[on_policy_received] Politika (Kaynak: {source}) uygulanıyor: {policy_type}, Parametreler: {policy_parameters}")

            success, result_msg = apply_policy(username, policy_type, policy_parameters)

            action = "policy_applied" if success else "policy_failed"

            details = {
                "username": user, 
                "policy_type": policy_type, 
                "parameters": policy_parameters, 
                "message": result_msg,
                "source": source,
                "client_uuid": client_uuid 
            }
            send_response(action, details) 
            
            if not success:
                logger.error(f"[on_policy_received] Politika uygulanamadı: {policy_type}, Hata: {result_msg}")

    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)

def apply_policy(username, policy_type, parameters):
    policy_function = getattr(policies, policy_type, None)
    
    if policy_function is None:
        error_msg = f"Tanımsız veya bulunamayan politika tipi: '{policy_type}'"
        logger.error(f"[apply_policy] {error_msg}")
        return False, error_msg

    logger.info(f"[apply_policy] Politika tipi: {policy_type}, Parametreler: {json.dumps(parameters)}")
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

def start_laps_worker(conn_params, uuid):
    try:
        worker = LapsWorker(conn_params, agent_uuid=uuid)
        worker.start()
    except Exception as e:
        logger.error(f"[LAPS worker] Hata: {e}")

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

    try:
        logger.info("Sistem başlatıldı. Sadece istemci bazlı politikalar için sunucuya bildirim gönderiliyor...")
        login_notify(None, conn_params, uuid) 
        logger.info("İstemci bazlı politika talebi gönderildi.")
    except Exception as e:
        logger.error(f"Başlangıçta istemci politikaları talep edilirken hata oluştu: {e}")

    login_detection_thread = threading.Thread(target=login_detection, kwargs={'conn_params': conn_params, 'uuid':uuid}, daemon=True)
    listen_for_policies_thread = threading.Thread(target=listen_for_policies, kwargs={'conn_params': conn_params,}, daemon=True)
    laps_thread = threading.Thread(target=start_laps_worker, kwargs={'conn_params': conn_params, 'uuid': uuid}, daemon=True)
    login_detection_thread.start()
    listen_for_policies_thread.start()
    laps_thread.start()
    
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()