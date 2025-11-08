# ---------- insert below your existing imports ----------
from flask import jsonify
import time
import sqlite3

# ---------- demo endpoints for 10 SQLi types ----------
# Attack list:
# 1. Tautology (boolean auth bypass)
# 2. UNION-based (read other tables / schema)
# 3. Error-based (leak error messages)
# 4. Blind boolean inference (response changes)
# 5. Time-based (simulated sleep on server)
# 6. Stacked queries / piggyback (using executescript)
# 7. Second-order SQLi (store-then-execute)
# 8. LIKE / wildcard injection
# 9. Comment injection (truncation)
#10. Schema-exposing (query sqlite_master)

# ---- Helper: returns plain text for demo (keeps templates optional) ----
def simple_text(text):
    return f"<pre>{text}</pre>"

# ---------- 1) Tautology (vuln + safe) ----------
@app.route('/demo/tautology/vuln', methods=['POST'])
def tautology_vuln():
    # POST { "username": "...", "password": "..." }
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    conn = get_db_connection()
    cur = conn.cursor()
    # vulnerable string concatenation -> attacker can inject ' OR '1'='1
    q = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    print("VULN tautology executing:", q)
    try:
        cur.execute(q)
        row = cur.fetchone()
        conn.close()
        return simple_text(f"Result: {row}")
    except Exception as e:
        conn.close()
        # vulnerable app shows raw error (demo only)
        return simple_text(f"ERROR (leak): {str(e)}")

@app.route('/demo/tautology/safe', methods=['POST'])
def tautology_safe():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT id, username FROM users WHERE username = ? AND password = ?"
    cur.execute(q, (username, password))
    row = cur.fetchone()
    conn.close()
    return simple_text(f"Result: {row}")

# ---------- 2) UNION-based (vuln + safe) ----------
# This demo expects we select two columns (username,email) normally.
@app.route('/demo/union/vuln')
def union_vuln():
    # query param ?id=...
    id_param = request.args.get('id', '1')
    conn = get_db_connection()
    cur = conn.cursor()
    # vulnerable concatenation
    q = f"SELECT username, '' as extra FROM users WHERE id = {id_param}"
    print("VULN union executing:", q)
    try:
        cur.execute(q)
        rows = cur.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        conn.close()
        return simple_text(f"ERROR: {e}")

@app.route('/demo/union/safe')
def union_safe():
    id_param = request.args.get('id', '1')
    conn = get_db_connection()
    cur = conn.cursor()
    # safe parameterization (treats input as data)
    q = "SELECT username, '' as extra FROM users WHERE id = ?"
    cur.execute(q, (id_param,))
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

# ---------- 3) Error-based (vuln + safe) ----------
@app.route('/demo/error/vuln')
def error_vuln():
    # attacker can inject something that causes a SQL syntax error; debug=True will show stack trace
    term = request.args.get('q', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = f"SELECT username FROM users WHERE username = '{term}'"
    print("VULN error executing:", q)
    try:
        cur.execute(q)
        rows = cur.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        conn.close()
        # VULNERABLE: return exception message (leaks SQL/DB internals)
        return simple_text(f"DB ERROR: {e}")

@app.route('/demo/error/safe')
def error_safe():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT username FROM users WHERE username = ?"
    try:
        cur.execute(q, (term,))
        rows = cur.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception:
        conn.close()
        # SAFE: generic message only
        return simple_text("An error occurred. Contact admin.")

# ---------- 4) Blind boolean (vuln + safe) ----------
# Demonstrates response difference (attacker must infer by checking responses)
@app.route('/demo/blind/vuln')
def blind_vuln():
    cond = request.args.get('cond', '')  # attacker crafts condition, e.g. "' OR (username='admin') --"
    conn = get_db_connection()
    cur = conn.cursor()
    q = f"SELECT username FROM users WHERE username = '{cond}'"
    print("VULN blind executing:", q)
    cur.execute(q)
    rows = cur.fetchall()
    conn.close()
    # Attacker can check len(rows) or response content to infer true/false
    return simple_text(f"Rows found: {len(rows)}")

@app.route('/demo/blind/safe')
def blind_safe():
    cond = request.args.get('cond', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT username FROM users WHERE username = ?"
    cur.execute(q, (cond,))
    rows = cur.fetchall()
    conn.close()
    return simple_text(f"Rows found: {len(rows)}")

# ---------- 5) Time-based (simulated) ----------
# SQLite doesn't have SLEEP — we simulate: vulnerable endpoint sleeps if attacker injects keyword "SLEEP"
@app.route('/demo/time/vuln')
def time_vuln():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = f"SELECT username FROM users WHERE username = '{term}'"
    print("VULN time executing:", q)
    # naive simulation: if attacker includes "SLEEP(3)" in q, server sleeps -> attacker measures delay
    if "SLEEP(" in term.upper():
        # *** simulate DB-induced delay (lab only) ***
        sleep_seconds = 3
        time.sleep(sleep_seconds)
        conn.close()
        return simple_text(f"Simulated SLEEP for {sleep_seconds} seconds (vulnerable)")
    try:
        cur.execute(q)
        rows = cur.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        conn.close()
        return simple_text(f"ERROR: {e}")

@app.route('/demo/time/safe')
def time_safe():
    term = request.args.get('q', '')
    # parameterized - even if attacker sends "SLEEP()", it's treated as data and won't cause server sleep
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT username FROM users WHERE username = ?"
    cur.execute(q, (term,))
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

# ---------- 6) Stacked queries / piggyback (vuln + safe) ----------
@app.route('/demo/stacked/vuln', methods=['POST'])
def stacked_vuln():
    # POST param 'input' - attacker can pass "1; DROP TABLE users; --" if we run executescript
    inp = request.form.get('input', '')
    conn = get_db_connection()
    cur = conn.cursor()
    # Vulnerable: using executescript allows multiple statements
    script = f"SELECT username FROM users WHERE id = {inp};"
    print("VULN stacked executescript:", script)
    try:
        cur.executescript(script)   # executescript allows semicolons
        # fetch results via a new select (executescript doesn't return rows), for demo run a safe select
        cur.execute("SELECT username FROM users")
        rows = cur.fetchall()
        conn.commit()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        conn.close()
        return simple_text(f"ERROR: {e}")

@app.route('/demo/stacked/safe', methods=['POST'])
def stacked_safe():
    inp = request.form.get('input', '')
    # SAFE: do not use executescript; use parameterized query and restrict to digits
    if not inp.isdigit():
        return simple_text("Invalid input")
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT username FROM users WHERE id = ?"
    cur.execute(q, (inp,))
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

# ---------- 7) Second-order SQLi (store-then-execute) ----------
#  - Step A: store profile (vulnerable store)
@app.route('/demo/second/store', methods=['POST'])
def second_store():
    # store value into a 'comments' table (create if needed)
    payload = request.form.get('payload', '')
    conn = get_db_connection()
    cur = conn.cursor()
    # create comments table if not exists
    cur.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT)")
    # vulnerable store (just stores the raw payload)
    cur.execute("INSERT INTO comments (content) VALUES (?)", (payload,))
    conn.commit()
    conn.close()
    return simple_text("Stored payload (vulnerable)")

#  - Step B: later admin view concatenates that stored content into a dynamic query (vulnerable)
@app.route('/demo/second/admin_view/vuln')
def second_admin_vuln():
    # vulnerable: builds SQL that uses stored content directly
    conn = get_db_connection()
    cur = conn.cursor()
    # fetch the stored payload (for demo assume id=1)
    cur.execute("SELECT content FROM comments")
    rows = cur.fetchall()
    outputs = []
    for (content,) in rows:
        # OOPS: imagine admin uses this stored content inside another SQL string via concat
        q = f"SELECT username FROM users WHERE username = '{content}'"
        print("Second-order vuln exec:", q)
        try:
            cur.execute(q)
            r = cur.fetchall()
        except Exception as e:
            r = [f"ERROR: {e}"]
        outputs.append({'stored': content, 'result': r})
    conn.close()
    return jsonify(outputs)

@app.route('/demo/second/admin_view/safe')
def second_admin_safe():
    # SAFE: treat stored content as untrusted and parameterize when using it
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT content FROM comments")
    rows = cur.fetchall()
    outputs = []
    for (content,) in rows:
        q = "SELECT username FROM users WHERE username = ?"
        cur.execute(q, (content,))
        r = cur.fetchall()
        outputs.append({'stored': content, 'result': r})
    conn.close()
    return jsonify(outputs)

# ---------- 8) LIKE / wildcard injection (vuln + safe) ----------
@app.route('/demo/like/vuln')
def like_vuln():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = f"SELECT username FROM users WHERE username LIKE '%{term}%'"
    print("VULN like executing:", q)
    cur.execute(q)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route('/demo/like/safe')
def like_safe():
    term = request.args.get('q', '')
    conn = get_db_connection()
    cur = conn.cursor()
    q = "SELECT username FROM users WHERE username LIKE ?"
    cur.execute(q, (f"%{term}%",))
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

# -----
