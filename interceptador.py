import paho.mqtt.client as mqtt

# Broker REAL (localhost)
REAL_BROKER = "127.0.0.1"
REAL_PORT = 1883

# Broker FAKE onde o chat se conecta
PROXY_BROKER = "0.0.0.0"
PROXY_PORT = 1884

# Cliente que conecta ao broker real
backend = mqtt.Client(client_id="interceptor-backend")

# Cliente que simula broker para o chat
proxy = mqtt.Client(client_id="interceptor-proxy")

# Quando o chat publica no PROXY
def on_proxy_message(client, userdata, msg):
    payload = msg.payload.decode()

    print(f"[INTERCEPTOR] Mensagem interceptada:")
    print(f" - Tópico: {msg.topic}")
    print(f" - Payload: {payload}")

    # ❌ BLOQUEAR: não repassar ao broker real
    print("[INTERCEPTOR] BLOQUEADA. Não será enviada ao destino.\n")
    return  # <- bloqueio

    # ✔ Para repassar, usar:
    # backend.publish(msg.topic, msg.payload)

def main():
    # Conectar ao broker real
    backend.connect(REAL_BROKER, REAL_PORT)

    # Fake broker: intercepta tudo que o chat publica
    proxy.on_message = on_proxy_message
    proxy.connect(PROXY_BROKER, PROXY_PORT)
    proxy.subscribe("#")  # interceptar todos os tópicos

    print(f"[INTERCEPTOR] Proxy MQTT iniciado em 0.0.0.0:{PROXY_PORT}")
    print(f"[INTERCEPTOR] Broker real em {REAL_BROKER}:{REAL_PORT}")

    proxy.loop_forever()

if __name__ == "__main__":
    main()
