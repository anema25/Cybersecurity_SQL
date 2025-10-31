import sqlite3

def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    c.execute("INSERT INTO users (username, password) VALUES ('user', 'user123')")
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect('app.db')
