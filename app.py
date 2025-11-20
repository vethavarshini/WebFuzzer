from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import json
import os
import threading
import time

app = Flask(__name__)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/run-fuzzer', methods=['POST'])
def run_fuzzer():
    try:
        data = request.get_json()
        url = data.get('url')
        name = data.get('name', 'Target Website')
        
        # Create input file for the fuzzer
        input_data = {
            'url': url,
            'name': name
        }
        
        with open('web_input.json', 'w') as f:
            json.dump(input_data, f)
        
        # Run the fuzzer in a separate thread
        def run_scan():
            try:
                # Run the fuzzer with the web input
                subprocess.run(['python', 'web_fuzzer.py'], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error running fuzzer: {e}")
        
        # Start the scan in background
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({'status': 'success', 'message': 'Scan started'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/report.html')
def serve_report():
    try:
        return send_file('report.html')
    except FileNotFoundError:
        return "Report not found. Please run a scan first.", 404

@app.route('/status')
def get_status():
    # Check if report exists to determine if scan is complete
    report_exists = os.path.exists('report.html')
    return jsonify({'complete': report_exists})

if __name__ == '__main__':
    print("🚀 Starting WebFuzzer Web Interface...")
    print("📱 Access the interface at: http://localhost:5000")
    print("🔒 Ready for security testing!")
    app.run(debug=True, host='0.0.0.0', port=5000)