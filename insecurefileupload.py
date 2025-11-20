import requests
import time
from pymongo import MongoClient

from dotenv import load_dotenv
import os
load_dotenv()
# MongoDB Atlas connection URI
MONGO_URI = os.getenv("MONGO_URL")
def get_file_upload_payloads():
    """
    Fetch remote code execution payloads for file upload testing from MongoDB.
    Each document should have: name, payload, category (optional).
    """
    try:
        print("Connecting to MongoDB Atlas for file upload payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["insecure_file_upload"]

        payloads = []
        for doc in collection.find():
            name = doc.get("name")
            content = doc.get("payload")
            category = doc.get("category", "Unknown")

            if name and content:
                filename = f"{name}.php"  # Assuming all are PHP payloads
                payloads.append((category, filename, content))

        print(f"Retrieved {len(payloads)} file upload payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"Error fetching payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()


def test_insecure_file_upload(upload_url, check_url):
    """
    Tests a file upload endpoint for insecure file upload vulnerabilities.
    Uploads dangerous payloads from MongoDB and checks for execution.
    """
    payloads = get_file_upload_payloads()
    vulnerabilities = []

    if not payloads:
        print("No payloads found. Skipping file upload test.\n")
        return vulnerabilities

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    print("Testing for Insecure File Upload...\n")

    for file_type, filename, content in payloads:
        files = {"file": (filename, content)}

        try:
            print(f"  Uploading {file_type} payload: {filename}...")
            time.sleep(2)

            response = requests.post(upload_url, files=files, headers=headers, timeout=10, verify=False)

            if response.status_code == 200:
                print(f"  {filename} uploaded! Checking execution...")

                time.sleep(2)
                execution_url = f"{check_url.rstrip('/')}/{filename}"
                execution_check = requests.get(execution_url, headers=headers, timeout=10, verify=False)

                if "Hacked" in execution_check.text:
                    print("  Vulnerability Found! File executed on server.\n")
                    vulnerabilities.append({
                        "type": "Insecure File Upload",
                        "payload": filename,
                        "recommendation": "Restrict allowed file types, validate content, and store uploads outside web root."
                    })
                else:
                    print("  File uploaded but not executed.\n")
            else:
                print(f"  Upload failed with status code: {response.status_code}\n")

        except requests.exceptions.RequestException as e:
            print(f"  Error testing {file_type}: {e}\n")

    return vulnerabilities
