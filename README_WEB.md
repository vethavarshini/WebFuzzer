# WebFuzzer - Advanced Security Testing Tool 🔒

A comprehensive web application security scanner with a modern web interface, powered by MongoDB Atlas for attack payloads and featuring OWASP Top 10 vulnerability detection.

## 🚀 Quick Start

### Option 1: Web Interface (Recommended)

```bash
# Start the web server
python web_server.py

# Or use the batch file
start_web_interface.bat
```

Then open your browser to `http://localhost:8080` - the interface will open automatically!

### Option 2: Terminal Interface

```bash
# Run the original terminal version
python Fuzzer.py
```

## ✨ Features

### 🎯 Security Tests

- **SQL Injection** - Detects database injection vulnerabilities
- **Cross-Site Scripting (XSS)** - Identifies XSS vulnerabilities
- **Command Injection** - Tests for command execution flaws
- **Directory Traversal** - Checks for path traversal issues
- **Broken Authentication** - Identifies authentication bypass
- **Security Misconfiguration** - Detects configuration issues
- **Sensitive Data Exposure** - Finds exposed sensitive information
- **Insecure File Upload** - Tests file upload security
- **Cross-Site Request Forgery (CSRF)** - Detects CSRF vulnerabilities
- **Insecure Direct Object References (IDOR)** - Finds IDOR issues
- **Brute Force Protection** - Tests login attempt limits

### 🔧 Technology Stack Detection

- Automatically identifies web technologies
- Maps known CVEs to detected versions
- Provides comprehensive vulnerability intelligence

### 📊 Modern Web Interface

- **Glass-morphism Design** with Tailwind CSS
- **Real-time Progress** tracking
- **Mobile Responsive** interface
- **Professional Reports** in HTML format
- **Easy-to-use** input validation

## 📋 Requirements

```bash
pip install -r requirements.txt
```

### Dependencies

- `pymongo` - MongoDB Atlas integration
- `python-Wappalyzer` - Technology detection
- `requests` - HTTP requests
- `python-dotenv` - Environment variables

## ⚙️ Configuration

### MongoDB Atlas Setup

1. Create a `.env` file in the project directory
2. Add your MongoDB connection string:

```env
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net/?appName=attack-payloads
```

## 🖥️ Web Interface Usage

1. **Start the Server:**

   ```bash
   python web_server.py
   ```

2. **Access the Interface:**

   - Automatically opens at `http://localhost:8080`
   - Enter target URL (e.g., `https://example.com`)
   - Optionally add a target name
   - Click "Start Security Scan"

3. **Monitor Progress:**

   - Real-time progress updates
   - Detailed scan step information
   - Automatic completion detection

4. **View Results:**
   - Click "View Detailed Report"
   - Professional HTML report with all findings
   - Vulnerability details and recommendations

## 📁 Project Structure

```
WebFuzzer/
├── index.html              # Web interface
├── web_server.py           # Local web server
├── web_fuzzer.py           # Web-compatible fuzzer
├── Fuzzer.py              # Original terminal fuzzer
├── start_web_interface.bat # Windows startup script
├── sqlinjection.py        # SQL injection tests
├── xss.py                 # XSS tests
├── commandinjection.py    # Command injection tests
├── directorytraversal.py  # Directory traversal tests
├── Brokenauthentication.py # Authentication tests
├── securitymisconfiguration.py # Misconfiguration tests
├── sensitivedataexposure.py # Data exposure tests
├── insecurefileupload.py  # File upload tests
├── csrf.py                # CSRF tests
├── idor.py                # IDOR tests
├── multipleloginattempts.py # Brute force tests
├── reportgeneration.py    # Report generation
├── threat_intel.py        # CVE intelligence
├── techstack_identification.py # Technology detection
└── requirements.txt       # Dependencies
```

## 🎨 Interface Features

- **Modern Design**: Glass-morphism effects with gradient backgrounds
- **Progress Tracking**: Real-time scan progress with emoji indicators
- **Security Showcase**: Visual representation of all security tests
- **Responsive Layout**: Works on desktop, tablet, and mobile
- **Professional Reports**: Detailed HTML reports with findings
- **Error Handling**: User-friendly error messages and validation

## 🛡️ Security Testing Process

1. **Technology Detection**: Identifies web stack and maps CVEs
2. **Payload Injection**: Uses MongoDB Atlas payload database
3. **Vulnerability Analysis**: Tests against OWASP Top 10
4. **Report Generation**: Creates comprehensive HTML reports
5. **Real-time Feedback**: Shows progress and findings as they occur

## 📊 Report Features

- Executive summary of findings
- Detailed vulnerability descriptions
- Risk ratings and recommendations
- Technical details and proof of concept
- Professional formatting for security assessments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any system.

## 🔧 Troubleshooting

### Common Issues:

- **MongoDB Connection**: Verify `.env` file and connection string
- **Port 8080 in use**: Change port in `web_server.py`
- **Missing dependencies**: Run `pip install -r requirements.txt`

### Getting Help:

- Check the console output for detailed error messages
- Ensure MongoDB Atlas is accessible
- Verify target URLs are reachable and properly formatted

## 🎯 Future Enhancements

- [ ] Real-time vulnerability notifications
- [ ] Custom payload management
- [ ] Scheduled scanning
- [ ] API endpoints for integration
- [ ] Advanced reporting formats
- [ ] Multi-target batch scanning
