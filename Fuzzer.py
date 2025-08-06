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
    url = input("Enter the website URL to test: ")

    print(f"\nStarting security tests on {url}...\n")

    vulnerabilities = []

    # Perform SQL Injection test
    print("🔍 Testing for SQL Injection...")
    sql_vulns = sqlinjection.test_sql_injection(url)
    vulnerabilities.extend(sql_vulns)
    print(f"✅ SQL Injection Test Completed. Found {len(sql_vulns)} vulnerabilities.\n")

    # Perform XSS test
    print("🔍 Testing for Cross-Site Scripting (XSS)...")
    xss_vulns = xss.test_xss(url)
    vulnerabilities.extend(xss_vulns)
    print(f"✅ XSS Test Completed. Found {len(xss_vulns)} vulnerabilities.\n")

    # Perform Command Injection test
    print("🔍 Testing for Command Injection...")
    cmd_vulns = commandinjection.test_command_injection(url)
    vulnerabilities.extend(cmd_vulns)
    print(f"✅ Command Injection Test Completed. Found {len(cmd_vulns)} vulnerabilities.\n")

    # Perform Directory Traversal test
    print("🔍 Testing for Directory Traversal...")
    dir_vulns = directorytraversal.test_directory_traversal(url)
    vulnerabilities.extend(dir_vulns)
    print(f"✅ Directory Traversal Test Completed. Found {len(dir_vulns)} vulnerabilities.\n")
    
    #Broken Authentication test
    print("🔍 Testing for Broken Authentication...")
    auth_vulns = Brokenauthentication.test_broken_authentication(url)
    vulnerabilities.extend(auth_vulns)
    print(f"✅ Broken Authentication Test Completed. Found {len(auth_vulns)} vulnerabilities.\n")
    
    #Security 
    print("🔍 Testing for Security Misconfiguration...")
    misconfig_vulns = securitymisconfiguration.test_security_misconfiguration(url)
    vulnerabilities.extend(misconfig_vulns)
    print(f"✅ Security Misconfiguration Test Completed. Found {len(misconfig_vulns)} vulnerabilities.\n")
    
    #sensitive Data E
    print("🔍 Testing for Sensitive Data Exposure...")
    sensitive_vulns = sensitivedataexposure.test_sensitive_data_exposure(url)
    vulnerabilities.extend(sensitive_vulns)
    print(f"✅ Sensitive Data Exposure Test Completed. Found {len(sensitive_vulns)} vulnerabilities.\n")
    
    upload_url = url + "/upload.php"  # Modify based on actual upload endpoint
    check_url = url + "/uploads"  # Modify based on actual file storage location

    print("🔍 Testing for Insecure File Upload...")
    file_upload_vulns = insecurefileupload.test_insecure_file_upload(upload_url, check_url)
    vulnerabilities.extend(file_upload_vulns)
    print(f"✅ Insecure File Upload Test Completed. Found {len(file_upload_vulns)} vulnerabilities.\n")
    
    
    # Perform CSRF test
    print("🔍 Testing for Cross-Site Request Forgery (CSRF)...")
    csrf_vulns = csrf.test_csrf(url)
    vulnerabilities.extend(csrf_vulns)
    print(f"✅ CSRF Test Completed. Found {len(csrf_vulns)} vulnerabilities.\n")
    
    # Perform IDOR test
    print("🔍 Testing for Insecure Direct Object References (IDOR)...")

    # Call the function
    idor_vulns = idor.test_idor(url)  # Ensure this function returns a list

    # Print detected vulnerabilities in the terminal
    for vuln in idor_vulns:
        print(f"❌ Found IDOR vulnerability: {vuln['payload']}")

    # Append to the main vulnerabilities list
    vulnerabilities.extend(idor_vulns)

    print(f"✅ IDOR Test Completed. Found {len(idor_vulns)} vulnerabilities.\n")
    
    # Perform Multiple Login Attempts test
    print("🔍 Testing for Multiple Login Attempts (Brute Force Protection)...")
    login_vulns = multipleloginattempts.test_multiple_login_attempts(url)
    vulnerabilities.extend(login_vulns)
    print(f"✅ Multiple Login Attempts Test Completed. Found {len(login_vulns)} vulnerabilities.\n")



    
    # Generate report
    print("📄 Generating Report...")
    reportgeneration.generate_report(name, url, vulnerabilities)
    print("✅ Security scan complete. Check 'report.html' for details.\n")
    

if __name__ == "__main__":
    main()
