import requests
from pymongo import MongoClient

# MongoDB Atlas connection URI
MONGO_URI = ""

def get_command_injection_payloads():
    """
    Fetch command injection payloads from MongoDB Atlas.
    """
    try:
        print("🔄 Connecting to MongoDB Atlas for command injection payloads...")
        client = MongoClient(MONGO_URI)
        db = client["attack_payloads_v1"]
        collection = db["command_injection"]

        cursor = collection.find({})
        payloads = []

        for doc in cursor:
            if "payload" in doc:
                payloads.append(doc["payload"])

        print(f"✅ Retrieved {len(payloads)} command injection payloads from MongoDB.\n")
        return payloads

    except Exception as e:
        print(f"❌ Error fetching payloads: {e}")
        return []

    finally:
        if 'client' in locals():
            client.close()


def test_command_injection(url):
    """
    Test for command injection vulnerabilities by injecting various payloads.
    """
    cmd_payloads = get_command_injection_payloads()
    vulnerabilities = []

    if not cmd_payloads:
        print("⚠️ No command injection payloads found. Skipping test.\n")
        return vulnerabilities

    for payload in cmd_payloads:
        test_url = f"{url}?cmd={payload}"  # Adjust based on parameter name in the app
        print(f"  🔹 Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            # Check for common outputs indicating command execution
            if any(keyword in response.text for keyword in ["root", "bin", "etc", "uid=", "Linux"]):
                vulnerabilities.append({
                    "type": "Command Injection",
                    "payload": payload,
                    "recommendation": "Sanitize user input and avoid unsanitized system calls."
                })
                print("  ❌ Vulnerability Found!\n")

        except requests.exceptions.RequestException:
            print("  ⚠️ Connection Error. Skipping payload.\n")

    return vulnerabilities
