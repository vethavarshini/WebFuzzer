import requests
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")

def get_sql_injection_payloads():
    """
    Fetch payloads for SQL Injection from MongoDB Atlas collection.
    Only fetch payloads with category 'Classic'.
    """
    try:
        print("🔄 Connecting to MongoDB Atlas...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]           # Database name
        collection = db["sql_injection"]            # Collection name

        cursor = collection.find({"category": "Classic"})
        payloads = [doc["payload"] for doc in cursor if "payload" in doc]

        print(f"✅ Retrieved {len(payloads)} SQL Injection payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"❌ Error fetching payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_sql_injection(url):
    """
    Tests the provided URL for SQL Injection vulnerabilities using payloads from MongoDB.
    """
    sql_payloads = get_sql_injection_payloads()
    vulnerabilities = []

    if not sql_payloads:
        print("⚠️ No payloads found. Skipping SQL Injection test.\n")
        return vulnerabilities

    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"  # Modify this based on actual injection point
        print(f"  🔹 Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "payload": payload,
                    "recommendation": "Use parameterized queries to prevent SQL injection."
                })
                print("  ❌ Vulnerability Found!")
        except requests.exceptions.RequestException as e:
            print(f"  ⚠️ Request error: {e}")

    return vulnerabilities
