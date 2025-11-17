#!/usr/bin/env python3
# chat_secure.py
# usage: python chat_secure.py <seu_nome> <nome_da_outra_pessoa>

import sys
import time
import base64
import os
import getpass
import threading

import paho.mqtt.client as mqtt

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Broker (para aprendizado use localhost ou seu broker local)
BROKER = "broker.hivemq.com"
PORT = 1883
KEEPALIVE = 60

TOPIC_BASE = "inteli/mqtt_chat_demo/"

# KDF parameters
KDF_ITERATIONS = 200_000
SALT_LEN = 16         # bytes
NONCE_LEN = 12        # bytes for AESGCM
KEY_LEN = 32          # 256-bit key


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Deriva uma chave AES-256 a partir da senha e salt usando PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password)


def encrypt_message(password: bytes, plaintext: str) -> str:
    """
    Retorna base64(salt || nonce || ciphertext).
    Cada mensagem tem salt e nonce randômicos para evitar reused-key issues.
    """
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = salt + nonce + ct
    return base64.b64encode(payload).decode("ascii")


def decrypt_message(password: bytes, b64_payload: str) -> str:
    """Tenta decifrar. Lança exceção em falha."""
    raw = base64.b64decode(b64_payload)
    if len(raw) < SALT_LEN + NONCE_LEN + 1:
        raise ValueError("payload curto demais")
    salt = raw[:SALT_LEN]
    nonce = raw[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = raw[SALT_LEN + NONCE_LEN:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8", errors="ignore")


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print("[MQTT] Conectado com sucesso ao broker!")
        rx_topic = userdata["rx_topic"]
        client.subscribe(rx_topic)
        print(f"[MQTT] Assinado para receber em: {rx_topic}")
    else:
        print(f"[MQTT] Falha na conexão. Código: {reason_code}")


def on_message(client, userdata, msg):
    # msg.payload é bytes
    password = userdata["password"]
    peer = userdata["peer_name"]

    payload_bytes = msg.payload
    try:
        payload_b64 = payload_bytes.decode("ascii")
    except Exception:
        # não-base64: mensagem não-encriptada ou corrompida
        print(f"\n[{peer}] (mensagem não-base64 ou corrompida) {payload_bytes!r}")
        print("> ", end="", flush=True)
        return

    try:
        plaintext = decrypt_message(password, payload_b64)
        print(f"\n[{peer}] {plaintext}")
    except Exception as e:
        # se falhar, mostrar aviso e o conteúdo bruto (base64)
        print(f"\n[{peer}] [NÃO DECIFRADO] payload base64: {payload_b64}")
    finally:
        print("> ", end="", flush=True)


def input_loop(client, tx_topic, password):
    print("Digite mensagens para enviar. Use '/sair' para encerrar.\n")
    while True:
        try:
            msg = input("> ")
            if msg.strip().lower() == "/sair":
                print("Encerrando chat...")
                client.disconnect()
                break
            # encriptar e publicar
            encrypted = encrypt_message(password, msg)
            client.publish(tx_topic, encrypted)
        except (EOFError, KeyboardInterrupt):
            print("\nSaindo...")
            client.disconnect()
            break


def main():
    if len(sys.argv) < 3:
        print("Uso: python chat_secure.py <seu_nome> <nome_da_outra_pessoa>")
        sys.exit(1)

    my_name = sys.argv[1]
    peer_name = sys.argv[2]

    rx_topic = TOPIC_BASE + my_name
    tx_topic = TOPIC_BASE + peer_name

    print(f"Seu nome: {my_name}")
    print(f"Você vai receber em: {rx_topic}")
    print(f"Você vai enviar para: {tx_topic}")
    print("-" * 50)

    # pede senha (não ecoa)
    pwd = getpass.getpass("Senha compartilhada (para derivar chave AES): ").encode("utf-8")
    if not pwd:
        print("Senha vazia não permitida.")
        sys.exit(1)

    userdata = {
        "rx_topic": rx_topic,
        "peer_name": peer_name,
        "password": pwd,
    }

    client = mqtt.Client(
        client_id=f"chat-{my_name}-{int(time.time())}",
        userdata=userdata,
        protocol=mqtt.MQTTv5,
    )

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT, KEEPALIVE)
    client.loop_start()

    try:
        input_loop(client, tx_topic, pwd)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
