import requests
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")
def get_csrf_payloads():
    """
    Fetch CSRF payloads from MongoDB Atlas.
    """
    try:
        print("Connecting to MongoDB Atlas for CSRF payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["csrf"]

        cursor = collection.find({})
        payloads = []

        for doc in cursor:
            if "payload" in doc:
                payloads.append(doc["payload"])

        print(f"Retrieved {len(payloads)} CSRF payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching CSRF payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()


def test_csrf(url):
    """
    Tests for CSRF vulnerability by submitting CSRF payloads without authentication headers.
    """
    payloads = get_csrf_payloads()
    vulnerabilities = []

    if not payloads:
        print("No CSRF payloads found. Skipping CSRF test.\n")
        return vulnerabilities

    print("Testing CSRF using payloads...\n")

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": url
    }

    for payload in payloads:
        try:
            print(f"  Sending CSRF payload to {url}/test_csrf_endpoint")

            # You would need to simulate the effect of the payload on a test endpoint.
            response = requests.post(f"{url}/test_csrf_endpoint", data={}, headers=headers)

            # Simulate detection (this would depend on your app's response behavior)
            if response.status_code == 200 and "Password changed successfully" in response.text:
                vulnerabilities.append({
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "payload": payload,
                    "recommendation": "Implement CSRF tokens, SameSite cookies, and referer/origin validation."
                })
                print("  CSRF Vulnerability Detected!\n")

        except requests.exceptions.RequestException as e:
            print(f"  Request failed: {e}")

    return vulnerabilities
