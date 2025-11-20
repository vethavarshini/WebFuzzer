import json
import os
import webbrowser
import time
import threading
import subprocess
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

# Global variables for scan state
scan_output = []
scan_completed = False
scan_running = False

class FuzzerHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        global scan_output, scan_completed, scan_running
        
        if self.path == '/run-fuzzer':
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                
                # Reset scan state
                scan_output = []
                scan_completed = False
                scan_running = True
                
                # Save input data
                with open('web_input.json', 'w') as f:
                    json.dump(data, f, indent=2)
                
                # Run the fuzzer with real-time output capture
                def run_fuzzer():
                    global scan_output, scan_completed, scan_running
                    try:
                        print(f"[SERVER] Starting fuzzer for {data['url']}")
                        scan_output.append("Starting security scan...")
                        scan_output.append(f"Target: {data['name']} - {data['url']}")
                        scan_output.append("Initializing WebFuzzer...")
                        print(f"[SERVER] Initial messages added, scan_output length: {len(scan_output)}")
                        
                        # Start the fuzzer process with real-time output
                        process = subprocess.Popen(
                            ['python', 'web_fuzzer.py'], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1,
                            universal_newlines=True
                        )
                        
                        # Read output line by line in real-time
                        print(f"[SERVER] Starting to read fuzzer output...")
                        for line in iter(process.stdout.readline, ''):
                            if line.strip():
                                scan_output.append(line.strip())
                                print(f"[FUZZER] {line.strip()}")
                                print(f"[SERVER] Total lines captured: {len(scan_output)}")
                        
                        process.stdout.close()
                        return_code = process.wait()
                        
                        if return_code == 0:
                            scan_output.append("Scan completed successfully!")
                            scan_output.append("Report generated: report.html")
                        else:
                            scan_output.append(f"Scan completed with exit code: {return_code}")
                            
                        scan_completed = True
                        scan_running = False
                        print("[SERVER] Fuzzer scan completed")
                        
                    except Exception as e:
                        scan_output.append(f"Error during scan: {str(e)}")
                        scan_completed = True
                        scan_running = False
                        print(f"[SERVER] Error: {e}")
                
                threading.Thread(target=run_fuzzer, daemon=True).start()
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = json.dumps({'status': 'success', 'message': 'Scan started'})
                self.wfile.write(response.encode())
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = json.dumps({'status': 'error', 'message': str(e)})
                self.wfile.write(response.encode())
        
        elif self.path == '/scan-status':
            # Endpoint to get real-time scan progress
            print(f"[SERVER] Status request - Running: {scan_running}, Completed: {scan_completed}, Output lines: {len(scan_output)}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps({
                'output': scan_output,
                'completed': scan_completed,
                'running': scan_running
            })
            self.wfile.write(response.encode())
        
        else:
            super().do_POST()
    
    def do_GET(self):
        global scan_output, scan_completed, scan_running
        
        if self.path == '/scan-status':
            # Handle GET request for scan status
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps({
                'output': scan_output,
                'completed': scan_completed,
                'running': scan_running
            })
            self.wfile.write(response.encode())
        else:
            super().do_GET()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def start_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, FuzzerHandler)
    
    print("WebFuzzer Interface Starting...")
    print("Opening web interface at: http://localhost:8080")
    print("Ready for security testing!")
    print("\nPress Ctrl+C to stop the server")
    
    # Open browser automatically
    webbrowser.open('http://localhost:8080/index.html')
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nWebFuzzer interface stopped.")
        httpd.shutdown()

if __name__ == "__main__":
    start_server()