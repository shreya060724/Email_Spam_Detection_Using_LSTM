import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('model/predictions.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  message TEXT,
                  prediction TEXT,
                  category TEXT,
                  spam_score REAL,
                  notspam_score REAL,
                  time TEXT)''')
    conn.commit()
    conn.close()

def log_prediction(message, prediction, category, spam_score, notspam_score):
    conn = sqlite3.connect('model/predictions.db')
    c = conn.cursor()
    c.execute('''INSERT INTO history (message, prediction, category, spam_score, notspam_score, time)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (message, prediction, category, spam_score, notspam_score,
               datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
