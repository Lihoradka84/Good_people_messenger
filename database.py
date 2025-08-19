# database.py
import sqlite3
import os

DB_PATH = "data/messages.db"

def init_db():
    if not os.path.exists("data"):
        os.makedirs("data")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            content BLOB,
            type TEXT,  -- 'text' or 'image'
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_message(sender, receiver, content, msg_type):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, content, type) VALUES (?, ?, ?, ?)",
              (sender, receiver, content, msg_type))
    conn.commit()
    conn.close()

def get_messages():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT sender, content, type, timestamp FROM messages ORDER BY timestamp")
    rows = c.fetchall()
    conn.close()
    return rows