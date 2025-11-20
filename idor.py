import requests
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")
def get_idor_payloads():
    """
    Fetch IDOR test payloads from MongoDB Atlas.
    """
    try:
        print("Connecting to MongoDB Atlas for IDOR payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["idor"]

        payloads = [doc["payload"] for doc in collection.find({}) if "payload" in doc]

        print(f"Retrieved {len(payloads)} IDOR payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching IDOR payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_idor(url):
    """
    Test for Insecure Direct Object Reference (IDOR) vulnerabilities.
    URL should include `{id}` as a placeholder for replacement.
    Example: https://example.com/user/{id}/profile
    """
    vulnerabilities = []
    test_ids = get_idor_payloads()

    if not test_ids:
        print("No IDOR payloads found. Skipping IDOR test.\n")
        return vulnerabilities

    print("Testing for IDOR vulnerabilities...\n")

    for test_id in test_ids:
        test_url = url.replace("{id}", str(test_id))

        try:
            response = requests.get(test_url, allow_redirects=False)

            if response.status_code not in [401, 403]:
                print(f"Potential IDOR at: {test_url}")
                vulnerabilities.append({
                    "type": "IDOR",
                    "payload": test_url,
                    "recommendation": "Implement proper authorization checks for resource access.",
                    "severity": "High"
                })

        except requests.RequestException as e:
            print(f"Error while testing IDOR for {test_url}: {e}")

    return vulnerabilities
