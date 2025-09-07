import requests
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")

def get_security_misconfiguration_payloads():
    """
    Fetch payloads for Security Misconfiguration from MongoDB Atlas.
    """
    try:
        print("🔄 Connecting to MongoDB Atlas for misconfiguration payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["security_misconfiguration"]

        # Fetch payloads with category "Security Misconfiguration"
        cursor = collection.find({"category": "Security Misconfiguration"})

        payloads = []
        for doc in cursor:
            payloads.append({
                "name": doc.get("name", "Unknown"),
                "path": doc.get("path", ""),
                "description": doc.get("description", ""),
                "recommendation": doc.get("recommendation", "No recommendation provided.")
            })

        print(f"✅ Retrieved {len(payloads)} misconfiguration payloads.\n")
        return payloads

    except Exception as e:
        print(f"❌ Error fetching misconfiguration payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_security_misconfiguration(base_url):
    """
    Test for common Security Misconfiguration issues using MongoDB payloads.
    """
    vulnerabilities = []
    payloads = get_security_misconfiguration_payloads()

    print("🔍 Testing for Security Misconfiguration...\n")

    if not payloads:
        print("⚠️ No misconfiguration payloads found. Skipping.\n")
        return vulnerabilities

    headers = {"User-Agent": "Mozilla/5.0"}

    for payload in payloads:
        test_url = base_url.rstrip("/") + "/" + payload["path"].lstrip("/")
        print(f"🚀 Testing payload: {payload['name']} at {test_url}")

        try:
            response = requests.get(test_url, headers=headers, timeout=10)
            if response.status_code == 200 and "error" not in response.text.lower():
                print(f"❌ Potential misconfiguration found at {test_url}")
                vulnerabilities.append({
                    "type": "Security Misconfiguration",
                    "payload": test_url,
                    "description": payload["description"],
                    "recommendation": payload["recommendation"]
                })
            else:
                print(f"✅ No issue at {test_url}")

        except requests.exceptions.RequestException as e:
            print(f"❌ Request error for {test_url}: {e}")

    return vulnerabilities
