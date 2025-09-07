import requests
import time

# Configuration for rate limiting
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # seconds (5 minutes)
LOGIN_URL = "/login"  # Modify to actual endpoint
LOGIN_PAYLOAD = {'username': 'admin', 'password': 'incorrect'}  # Dummy creds for testing

login_attempts = {}

def test_multiple_login_attempts(base_url):
    """
    Tests for brute-force attacks by making multiple failed login attempts
    and checking if rate limiting or blocking is applied.
    """
    vulnerabilities = []

    print("🔐 Testing for brute-force login protections...\n")

    for attempt in range(MAX_ATTEMPTS + 2):  # Extra attempts to check for blocking
        try:
            full_url = base_url.rstrip("/") + LOGIN_URL

            response = requests.post(full_url, data=LOGIN_PAYLOAD)

            # Log each attempt
            print(f"  🔁 Attempt {attempt + 1}: Status Code = {response.status_code}")

            # Small delay to simulate realistic brute-force pace
            time.sleep(1)

            ip_address = response.request.headers.get('X-Forwarded-For', '127.0.0.1')
            current_time = time.time()

            if ip_address not in login_attempts:
                login_attempts[ip_address] = []

            login_attempts[ip_address].append(current_time)

            # Retain only recent attempts within BLOCK_TIME
            recent_attempts = [t for t in login_attempts[ip_address] if current_time - t < BLOCK_TIME]
            login_attempts[ip_address] = recent_attempts

            # If no blocking observed after all attempts
            if attempt == MAX_ATTEMPTS + 1 and len(recent_attempts) > MAX_ATTEMPTS:
                vulnerabilities.append({
                    "type": "Brute Force / Multiple Login Attempts",
                    "payload": f"Too many failed login attempts from IP: {ip_address} without blocking",
                    "recommendation": "Implement account lockout, IP blocking, or CAPTCHA after multiple failed login attempts.",
                    "severity": "High"
                })

        except requests.exceptions.RequestException as e:
            print(f"  ⚠️ Error during attempt {attempt + 1}: {e}")
            time.sleep(2)

    if not vulnerabilities:
        print("✅ No brute-force vulnerability detected.\n")

    return vulnerabilities
