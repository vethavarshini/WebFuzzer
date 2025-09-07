import requests
import re
from pymongo import MongoClient

# MongoDB Atlas connection URI
MONGO_URI = ""

def get_sensitive_patterns():
    """
    Fetch sensitive data regex patterns from MongoDB.
    Filters by category: 'Sensitive Data'.
    """
    try:
        print("🔄 Connecting to MongoDB Atlas for sensitive data patterns...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["sensitive_data_exposure"]

        cursor = collection.find({"category": "Sensitive Data"})
        patterns = {doc["name"]: doc["pattern"] for doc in cursor if "name" in doc and "pattern" in doc}

        print(f"✅ Retrieved {len(patterns)} sensitive data patterns.\n")
        return patterns

    except Exception as e:
        print(f"❌ Error fetching patterns: {e}")
        return {}

    finally:
        if 'client' in locals():
            client.close()


def test_sensitive_data_exposure(url):
    """
    Tests the given URL for sensitive data exposure using regex patterns from MongoDB.
    """
    vulnerabilities = []
    patterns = get_sensitive_patterns()

    print("🔍 Testing for Sensitive Data Exposure...\n")

    if not patterns:
        print("⚠️ No sensitive data patterns found. Skipping test.\n")
        return vulnerabilities

    try:
        response = requests.get(url, timeout=5)
        content = response.text

        for name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                print(f"❌ {name} found: {matches[:3]} (Showing first 3 matches)")
                vulnerabilities.append({
                    "type": "Sensitive Data Exposure",
                    "payload": f"{name} - {matches[:3]}",
                    "recommendation": "Remove sensitive data from public-facing pages and use environment variables."
                })

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Request failed: {e}")

    return vulnerabilities
