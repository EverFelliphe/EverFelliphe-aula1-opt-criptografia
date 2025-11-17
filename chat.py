# pip install paho-mqtt
# python chat_mqtt.py sender receiver

import paho.mqtt.client as mqtt
import threading
import sys
import time

# Configurações do broker público (pode trocar pelo da sua infra)
BROKER = "broker.hivemq.com"
PORT = 1883
KEEPALIVE = 60

# Prefixo do tópico (use algo "único" pra sua simulação)
TOPIC_BASE = "inteli/mqtt_chat_demo/"


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print("[MQTT] Conectado com sucesso ao broker!")
        # Assina o tópico de recebimento definido no userdata
        rx_topic = userdata["rx_topic"]
        client.subscribe(rx_topic)
        print(f"[MQTT] Assinado para receber em: {rx_topic}")
    else:
        print(f"[MQTT] Falha na conexão. Código: {reason_code}")


def on_message(client, userdata, msg):
    # Decodifica mensagem recebida
    payload = msg.payload.decode("utf-8", errors="ignore")
    sender = userdata["peer_name"]
    print(f"\n[{sender}] {payload}")
    print("> ", end="", flush=True)


def input_loop(client, tx_topic):
    print("Digite mensagens para enviar. Use '/sair' para encerrar.\n")
    while True:
        try:
            msg = input("> ")
            if msg.strip().lower() == "/sair":
                print("Encerrando chat...")
                client.disconnect()
                break
            # Publica no tópico de envio
            client.publish(tx_topic, msg)
        except (EOFError, KeyboardInterrupt):
            print("\nSaindo...")
            client.disconnect()
            break


def main():
    if len(sys.argv) < 3:
        print("Uso: python chat_mqtt.py <seu_nome> <nome_da_outra_pessoa>")
        print("Exemplo: python chat_mqtt.py alice bob")
        sys.exit(1)

    my_name = sys.argv[1]
    peer_name = sys.argv[2]

    # Tópicos:
    # - Você recebe no tópico com o seu nome
    # - Você envia no tópico com o nome do outro
    rx_topic = TOPIC_BASE + my_name
    tx_topic = TOPIC_BASE + peer_name

    print(f"Seu nome: {my_name}")
    print(f"Você vai receber em: {rx_topic}")
    print(f"Você vai enviar para: {tx_topic}")
    print("-" * 50)

    # userdata carrega infos extras para os callbacks
    userdata = {
        "rx_topic": rx_topic,
        "peer_name": peer_name,
    }

    client = mqtt.Client(
        client_id=f"chat-{my_name}-{int(time.time())}",
        userdata=userdata,
        protocol=mqtt.MQTTv5,
    )

    client.on_connect = on_connect
    client.on_message = on_message

    # Conecta ao broker
    client.connect(BROKER, PORT, KEEPALIVE)

    # Inicia loop de rede em thread separada
    client.loop_start()

    # Loop de input no thread principal
    try:
        input_loop(client, tx_topic)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
