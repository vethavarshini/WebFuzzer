import requests
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")
def get_directory_traversal_payloads():
    """
    Fetch directory traversal payloads from MongoDB.
    """
    try:
        print("Connecting to MongoDB Atlas for directory traversal payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["directory_traversal"]  # Make sure this collection exists

        cursor = collection.find({})
        payloads = []

        for doc in cursor:
            if "payload" in doc:
                payloads.append(doc["payload"])

        print(f"Retrieved {len(payloads)} traversal payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching traversal payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()

def test_directory_traversal(url):
    """
    Tests for Directory Traversal vulnerabilities using payloads from MongoDB.
    """
    traversal_payloads = get_directory_traversal_payloads()
    vulnerabilities = []

    if not traversal_payloads:
        print("No directory traversal payloads found. Skipping test.\n")
        return vulnerabilities

    print("Testing for Directory Traversal vulnerabilities...\n")

    for payload in traversal_payloads:
        test_url = f"{url}?file={payload}"  # Adjust based on parameter name
        print(f"  Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            if "root:" in response.text or "NT AUTHORITY" in response.text:
                print("  Vulnerability Found!")
                vulnerabilities.append({
                    "type": "Directory Traversal",
                    "payload": payload,
                    "recommendation": "Restrict file access and validate user input."
                })

        except requests.exceptions.RequestException:
            print("  Connection Error. Skipping payload.")

    return vulnerabilities
