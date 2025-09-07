import sqlinjection
import xss
import commandinjection
import directorytraversal
import reportgeneration
import Brokenauthentication
import securitymisconfiguration
import sensitivedataexposure
import insecurefileupload
import csrf
import idor
import multipleloginattempts

def main():
    print("\n===============================")
    print("     Welcome to Web Fuzzer      ")
    print("===============================\n")

    name = input("Enter your name: ")
    url = input("Enter the website URL to test (e.g., http://example.com): ").rstrip("/")

    print(f"\n🌐 Starting security tests on {url}...\n")
    vulnerabilities = []

    # SQL Injection
    print("🔍 Testing for SQL Injection...")
    sql_vulns = sqlinjection.test_sql_injection(url)
    vulnerabilities.extend(sql_vulns)
    print(f"✅ SQL Injection Test Completed. Found {len(sql_vulns)} vulnerabilities.\n")

    # XSS
    print("🔍 Testing for Cross-Site Scripting (XSS)...")
    xss_vulns = xss.test_xss(url)
    vulnerabilities.extend(xss_vulns)
    print(f"✅ XSS Test Completed. Found {len(xss_vulns)} vulnerabilities.\n")

    # Command Injection
    print("🔍 Testing for Command Injection...")
    cmd_vulns = commandinjection.test_command_injection(url)
    vulnerabilities.extend(cmd_vulns)
    print(f"✅ Command Injection Test Completed. Found {len(cmd_vulns)} vulnerabilities.\n")

    # Directory Traversal
    print("🔍 Testing for Directory Traversal...")
    dir_vulns = directorytraversal.test_directory_traversal(url)
    vulnerabilities.extend(dir_vulns)
    print(f"✅ Directory Traversal Test Completed. Found {len(dir_vulns)} vulnerabilities.\n")

    # Broken Authentication
    print("🔍 Testing for Broken Authentication...")
    auth_vulns = Brokenauthentication.test_broken_authentication(url)
    vulnerabilities.extend(auth_vulns)
    print(f"✅ Broken Authentication Test Completed. Found {len(auth_vulns)} vulnerabilities.\n")

    # Security Misconfiguration
    print("🔍 Testing for Security Misconfiguration...")
    misconfig_vulns = securitymisconfiguration.test_security_misconfiguration(url)
    vulnerabilities.extend(misconfig_vulns)
    print(f"✅ Security Misconfiguration Test Completed. Found {len(misconfig_vulns)} vulnerabilities.\n")

    # Sensitive Data Exposure
    print("🔍 Testing for Sensitive Data Exposure...")
    sensitive_vulns = sensitivedataexposure.test_sensitive_data_exposure(url)
    vulnerabilities.extend(sensitive_vulns)
    print(f"✅ Sensitive Data Exposure Test Completed. Found {len(sensitive_vulns)} vulnerabilities.\n")

    # Insecure File Upload (adjust endpoint as needed)
    upload_url = url + "/upload.php"   # Example upload endpoint
    check_url = url + "/uploads"       # Example upload location

    print("🔍 Testing for Insecure File Upload...")
    file_upload_vulns = insecurefileupload.test_insecure_file_upload(upload_url, check_url)
    vulnerabilities.extend(file_upload_vulns)
    print(f"✅ Insecure File Upload Test Completed. Found {len(file_upload_vulns)} vulnerabilities.\n")

    # CSRF
    print("🔍 Testing for Cross-Site Request Forgery (CSRF)...")
    csrf_vulns = csrf.test_csrf(url)
    vulnerabilities.extend(csrf_vulns)
    print(f"✅ CSRF Test Completed. Found {len(csrf_vulns)} vulnerabilities.\n")

    # IDOR
    print("🔍 Testing for Insecure Direct Object References (IDOR)...")
    idor_vulns = idor.test_idor(url)
    for vuln in idor_vulns:
        print(f"❌ Found IDOR vulnerability: {vuln['payload']}")
    vulnerabilities.extend(idor_vulns)
    print(f"✅ IDOR Test Completed. Found {len(idor_vulns)} vulnerabilities.\n")

    # Multiple Login Attempts
    print("🔍 Testing for Multiple Login Attempts (Brute Force)...")
    login_vulns = multipleloginattempts.test_multiple_login_attempts(url)
    vulnerabilities.extend(login_vulns)
    print(f"✅ Multiple Login Attempts Test Completed. Found {len(login_vulns)} vulnerabilities.\n")

    # Report Generation
    print("📄 Generating Report...")
    reportgeneration.generate_report(name, url, vulnerabilities)
    print("✅ Security scan complete. Report saved as 'report.html'.\n")

if __name__ == "__main__":
    main()
