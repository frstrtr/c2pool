#!/usr/bin/env python3
"""
Simple Stratum Test for C2Pool
"""

import socket
import json
import time

def test_stratum_simple():
    print("🔗 Testing C2Pool Stratum Connection")
    print("=" * 40)
    
    try:
        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(("127.0.0.1", 8085))
        print("✅ Connected to 127.0.0.1:8085")
        
        # Send subscribe
        subscribe_msg = {
            "id": 1,
            "method": "mining.subscribe", 
            "params": ["test-miner/1.0"]
        }
        
        msg = json.dumps(subscribe_msg) + "\\n"
        sock.send(msg.encode())
        print(f"📤 Sent: {msg.strip()}")
        
        # Wait for response
        print("⏳ Waiting for response...")
        time.sleep(2)
        
        try:
            data = sock.recv(1024).decode()
            print(f"📥 Received: {data}")
            
            if data:
                # Try to authorize with a valid address
                auth_msg = {
                    "id": 2,
                    "method": "mining.authorize",
                    "params": ["n4HFXoG2xEKFyzpGarucZzAd98seabNTPq", "password"]
                }
                
                msg = json.dumps(auth_msg) + "\\n" 
                sock.send(msg.encode())
                print(f"📤 Sent auth: {msg.strip()}")
                
                time.sleep(2)
                
                try:
                    auth_data = sock.recv(1024).decode()
                    print(f"📥 Auth response: {auth_data}")
                except socket.timeout:
                    print("⏰ Auth response timeout")
                    
        except socket.timeout:
            print("⏰ Subscribe response timeout")
        
        sock.close()
        print("🔌 Disconnected")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_stratum_simple()
