#!/usr/bin/env python3
"""
Enhanced Stratum test to capture all server responses
"""

import socket
import json
import time
import threading

def stratum_debug_test():
    print("🔬 Enhanced Stratum Protocol Debug Test")
    print("=" * 50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(("127.0.0.1", 8085))
        print("✅ Connected to 127.0.0.1:8085")
        
        # Set up a receiver thread to capture all responses
        responses = []
        receiving = True
        
        def receive_thread():
            """Background thread to receive and log all responses"""
            nonlocal receiving, responses
            buffer = ""
            while receiving:
                try:
                    data = sock.recv(1024).decode()
                    if data:
                        buffer += data
                        # Split by newlines and process complete JSON messages
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line.strip():
                                print(f"📥 RAW: {line.strip()}")
                                try:
                                    parsed = json.loads(line.strip())
                                    responses.append(parsed)
                                    print(f"📦 PARSED: {parsed}")
                                except json.JSONDecodeError as e:
                                    print(f"🚫 JSON Error: {e}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if receiving:
                        print(f"❌ Receive error: {e}")
                    break
        
        # Start receiver thread
        receiver = threading.Thread(target=receive_thread, daemon=True)
        receiver.start()
        
        # Test 1: Send subscribe
        print("\n🔗 TEST 1: mining.subscribe")
        subscribe_msg = {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["debug-miner/1.0"]
        }
        
        message = json.dumps(subscribe_msg) + "\n"
        sock.send(message.encode())
        print(f"📤 Sent: {message.strip()}")
        
        # Wait for response
        time.sleep(3)
        
        if responses:
            print("✅ Received subscribe response!")
            subscribe_response = responses[-1]
            
            # Test 2: Send authorize with valid address
            print("\n🔐 TEST 2: mining.authorize")
            auth_msg = {
                "id": 2,
                "method": "mining.authorize",
                "params": ["n4HFXoG2xEKFyzpGarucZzAd98seabNTPq", "password"]
            }
            
            message = json.dumps(auth_msg) + "\n"
            sock.send(message.encode())
            print(f"📤 Sent: {message.strip()}")
            
            # Wait for response
            time.sleep(3)
            
            # Test 3: Check for mining notifications
            print("\n⚡ TEST 3: Check for mining notifications")
            time.sleep(2)
            
        else:
            print("❌ No subscribe response received")
        
        print(f"\n📊 Total responses received: {len(responses)}")
        for i, resp in enumerate(responses):
            print(f"   {i+1}: {resp}")
        
        receiving = False
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    stratum_debug_test()
