import requests
from pymongo import MongoClient
from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")

# Safe print function for Windows console
def safe_print(message):
    """Print message with Unicode safety for Windows console"""
    try:
        if isinstance(message, str):
            # Replace problematic Unicode with ASCII equivalent or remove
            safe_message = message.encode('ascii', 'replace').decode('ascii')
            print(safe_message)
        else:
            print(str(message))
    except Exception:
        print("[Output contains unsupported characters]")

def get_authentication_payloads():
    """
    Fetch authentication bypass payloads (e.g., SQL login bypass, weak credentials) from MongoDB.
    """
    try:
        print("Connecting to MongoDB Atlas for authentication payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["broken_authentication"]

        cursor = collection.find({})
        payloads = []

        for doc in cursor:
            if "payload" in doc:
                payloads.append(doc["payload"])

        print(f"Retrieved {len(payloads)} authentication payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_broken_authentication(url):
    """
    Test for broken authentication vulnerabilities such as weak credentials and login bypass.
    """
    vulnerabilities = []
    login_url = f"{url}/login.php"  # Modify based on your actual login endpoint

    print("Testing for Broken Authentication...")

    payloads = get_authentication_payloads()
    if not payloads:
        print("No authentication payloads found. Skipping test.")
        return vulnerabilities

    for payload in payloads:
        # Assuming payloads are intended for username or password bypass
        data = {"username": payload, "password": payload}

        try:
            session = requests.Session()
            response = session.post(login_url, data=data, timeout=5)

            if "incorrect" not in response.text.lower() and response.status_code == 200:
                safe_print(f"Weak/Broken authentication bypassed with: {payload}")
                vulnerabilities.append({
                    "type": "Broken Authentication",
                    "payload": payload,
                    "recommendation": "Implement secure authentication logic, input sanitization, and account lockouts."
                })

            # Session Fixation test
            session_token_before = session.cookies.get_dict()
            session.post(login_url, data=data)
            session_token_after = session.cookies.get_dict()

            if session_token_before == session_token_after:
                print("Session Fixation detected!")
                vulnerabilities.append({
                    "type": "Session Fixation",
                    "payload": payload,
                    "recommendation": "Regenerate session tokens after successful authentication."
                })

        except requests.exceptions.RequestException:
            print("Connection error. Skipping this payload.")

    return vulnerabilities
