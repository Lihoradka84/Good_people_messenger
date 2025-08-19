# main.py
import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading
import os
from crypto import generate_keys, load_private_key, load_public_key, decrypt_message, encrypt_message
from database import init_db, save_message, get_messages
import socket
import pickle

# Настройки
HOST = '127.0.0.1'
PORT = 65432
PEER_PUBLIC_KEY = "keys/peer_public_key.pem"  # Публичный ключ собеседника

class MessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messenger")
        self.root.geometry("600x700")

        self.chat_log = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD)
        self.chat_log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.msg_entry = tk.Entry(root, width=80)
        self.msg_entry.pack(pady=5, side=tk.LEFT, padx=10)

        self.send_btn = tk.Button(root, text="Отправить", command=self.send_text)
        self.send_btn.pack(pady=5, side=tk.LEFT)

        self.photo_btn = tk.Button(root, text="Фото", command=self.send_photo)
        self.photo_btn.pack(pady=5, side=tk.LEFT)

        # Генерация ключей при старте
        if not os.path.exists("keys/private_key.pem"):
            generate_keys()

        self.private_key = load_private_key()
        self.peer_public_key = None

        init_db()
        self.load_messages()

        # Запуск приёмника в отдельном потоке
        threading.Thread(target=self.listen, daemon=True).start()

    def load_messages(self):
        self.chat_log.config(state='normal')
        for sender, content, msg_type, timestamp in get_messages():
            if msg_type == 'text':
                self.chat_log.insert(tk.END, f"[{timestamp}] {sender}: {content.decode()}\n")
            else:
                self.chat_log.insert(tk.END, f"[{timestamp}] {sender}: [Фото]\n")
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)

    def send_text(self):
        text = self.msg_entry.get().strip()
        if not text:
            return

        if not self.peer_public_key:
            self.peer_public_key = load_public_key(PEER_PUBLIC_KEY)

        encrypted = encrypt_message(self.peer_public_key, text.encode())
        save_message("Me", "Friend", encrypted, "text")
        self.send_to_peer({"type": "text", "data": encrypted})

        self.msg_entry.delete(0, tk.END)
        self.load_messages()

    def send_photo(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.png *.jpeg")])
        if not path:
            return

        from PIL import Image
        import io

        img = Image.open(path)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        # Шифруем изображение
        if not self.peer_public_key:
            self.peer_public_key = load_public_key(PEER_PUBLIC_KEY)

        # Делим на части, если слишком большой
        MAX_SIZE = 190  # Ограничение RSA
        chunks = [img_data[i:i+MAX_SIZE] for i in range(0, len(img_data), MAX_SIZE)]
        encrypted_chunks = [encrypt_message(self.peer_public_key, chunk) for chunk in chunks]
        encrypted_data = pickle.dumps(encrypted_chunks)

        save_message("Me", "Friend", encrypted_data, "image")
        self.send_to_peer({"type": "image", "data": encrypted_data})

        self.load_messages()

    def send_to_peer(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(pickle.dumps(data))
        except Exception as e:
            print("Не удалось отправить:", e)

    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print("Ожидание подключений...")

        while True:
            conn, addr = server.accept()
            with conn:
                data = b""
                while True:
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                try:
                    msg = pickle.loads(data)
                    self.handle_incoming(msg)
                except Exception as e:
                    print("Ошибка приёма:", e)

    def handle_incoming(self, msg):
        data_type = msg["type"]
        encrypted_data = msg["data"]

        if data_type == "text":
            decrypted = decrypt_message(self.private_key, encrypted_data).decode()
            save_message("Friend", "Me", encrypted_data, "text")  # зашифрованное
            self.chat_log.config(state='normal')
            self.chat_log.insert(tk.END, f"[Incoming] Friend: {decrypted}\n")
            self.chat_log.config(state='disabled')
            self.chat_log.yview(tk.END)

        elif data_type == "image":
            encrypted_chunks = pickle.loads(encrypted_data)
            decrypted_chunks = [
                decrypt_message(self.private_key, chunk) for chunk in encrypted_chunks
            ]
            full_image = b"".join(decrypted_chunks)

            # Сохраняем фото
            photo_path = f"data/received_{len(get_messages())}.png"
            with open(photo_path, "wb") as f:
                f.write(full_image)

            save_message("Friend", "Me", encrypted_data, "image")
            self.chat_log.config(state='normal')
            self.chat_log.insert(tk.END, f"[Incoming] Friend: [Фото: {photo_path}]\n")
            self.chat_log.config(state='disabled')
            self.chat_log.yview(tk.END)