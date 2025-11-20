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
            safe_message = message.encode('ascii', 'replace').decode('ascii')
            print(safe_message)
        else:
            print(str(message))
    except Exception:
        print("[Output contains unsupported characters]")

def get_xss_payloads():
    """
    Fetch payloads for Reflected XSS from MongoDB Atlas collection.
    """
    try:
        print("Connecting to MongoDB Atlas for XSS payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["xss"]

        # Optional debug print to confirm documents
        count = collection.count_documents({})
        print(f"📦 Total documents in collection: {count}")

        # Correct query: Case-sensitive match on 'Reflected XSS'
        cursor = collection.find({"category": "Reflected XSS"})
        payloads = [doc["payload"] for doc in cursor if "payload" in doc]

        print(f"Retrieved {len(payloads)} XSS payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching XSS payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_xss(url):
    """
    Tests the given URL for Reflected XSS using payloads from MongoDB.
    """
    xss_payloads = get_xss_payloads()
    vulnerabilities = []

    if not xss_payloads:
        print("No XSS payloads found. Skipping XSS test.\n")
        return vulnerabilities

    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"  # Adjust parameter as needed
        print(f"  Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                vulnerabilities.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "payload": payload,
                    "recommendation": "Use CSP and sanitize inputs."
                })
                print("  Vulnerability Found!")

        except requests.exceptions.RequestException as e:
            print(f"  Request error: {e}")

    return vulnerabilities

