from flask import Flask, request, render_template
import sqlite3
from database import get_db_connection

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# -------------------- Vulnerable Login --------------------
@app.route('/vulnerable/login', methods=['GET', 'POST'])
def login_vulnerable():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # ❌ VULNERABLE QUERY (direct string concat)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing:", query)
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()

        if result:
            msg = f"✅ Welcome {username}!"
        else:
            msg = "❌ Invalid credentials"

    return render_template('login_vulnerable.html', msg=msg)

# -------------------- Secure Login --------------------
@app.route('/secure/login', methods=['GET', 'POST'])
def login_secure():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ SAFE QUERY (parameterized)
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        conn.close()

        if result:
            msg = f"✅ Welcome {username}!"
        else:
            msg = "❌ Invalid credentials"

    return render_template('login_secure.html', msg=msg)


# -------------------- Vulnerable Search --------------------
@app.route('/vulnerable/search', methods=['GET'])
def search_vulnerable():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()

    # ❌ VULNERABLE: allows UNION/OR/-- injection
    query = f"SELECT username FROM users WHERE username LIKE '%{term}%'"
    print("Executing:", query)
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return render_template('search_vulnerable.html', term=term, results=results)

# -------------------- Secure Search --------------------
@app.route('/secure/search', methods=['GET'])
def search_secure():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ SAFE
    query = "SELECT username FROM users WHERE username LIKE ?"
    cursor.execute(query, (f"%{term}%",))
    results = cursor.fetchall()
    conn.close()
    return render_template('search_secure.html', term=term, results=results)

if __name__ == '__main__':
    app.run(debug=True)
