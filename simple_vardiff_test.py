#!/usr/bin/env python3
"""
Simple VARDIFF Test for C2Pool
Tests the variable difficulty adjustment by connecting a single miner
and monitoring difficulty changes.
"""

import socket
import json
import time
import threading

class SimpleMiner:
    def __init__(self, address: str = "tltc1qrqxtj6u4x3xd3jjk4xe8gp8fv2z6pvkl5ld6z5"):
        self.address = address
        self.socket = None
        self.difficulty = 1.0
        self.share_count = 0
        self.difficulty_changes = []
        
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("localhost", 8084))
        print(f"✅ Connected to Stratum server")
        
    def send_message(self, msg):
        self.socket.send((json.dumps(msg) + "\n").encode())
        
    def recv_message(self):
        data = ""
        while True:
            chunk = self.socket.recv(1024).decode()
            data += chunk
            if "\n" in data:
                break
        return json.loads(data.strip().split('\n')[0])
        
    def subscribe(self):
        self.send_message({
            "id": 1,
            "method": "mining.subscribe",
            "params": ["SimpleVardiffTest"]
        })
        
        response = self.recv_message()
        print(f"Subscribe response: {response}")
        return response.get("result") is not None
        
    def authorize(self):
        self.send_message({
            "id": 2,
            "method": "mining.authorize", 
            "params": [self.address, "password"]
        })
        
        response = self.recv_message()
        print(f"Authorize response: {response}")
        return response.get("result") == True
        
    def listen_notifications(self):
        """Listen for notifications in background"""
        while True:
            try:
                self.socket.settimeout(1.0)
                data = self.socket.recv(1024).decode()
                if not data:
                    break
                    
                for line in data.strip().split('\n'):
                    if line:
                        try:
                            msg = json.loads(line)
                            if "method" in msg and msg["method"] == "mining.set_difficulty":
                                old_diff = self.difficulty
                                self.difficulty = msg["params"][0]
                                self.difficulty_changes.append({
                                    "time": time.time(),
                                    "old": old_diff,
                                    "new": self.difficulty,
                                    "shares": self.share_count
                                })
                                print(f"🎯 DIFFICULTY ADJUSTED: {old_diff:.2f} → {self.difficulty:.2f} (after {self.share_count} shares)")
                        except:
                            continue
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Notification listener error: {e}")
                break
                
    def submit_share(self):
        import random
        
        # Generate fake share data
        job_id = f"job_{int(time.time())}"
        extranonce2 = f"{random.randint(0, 0xFFFFFFFF):08x}"
        ntime = f"{int(time.time()):08x}"
        nonce = f"{random.randint(0, 0xFFFFFFFF):08x}"
        
        self.send_message({
            "id": 100 + self.share_count,
            "method": "mining.submit",
            "params": [self.address, job_id, extranonce2, ntime, nonce]
        })
        
        try:
            response = self.recv_message()
            if response.get("result") == True:
                self.share_count += 1
                print(f"✅ Share #{self.share_count} accepted (difficulty: {self.difficulty:.2f})")
                return True
            else:
                print(f"❌ Share rejected: {response}")
                return False
        except:
            return False
            
    def mine(self, duration=120, rate=2.0):
        """Mine for duration seconds at specified rate (shares/second)"""
        if not self.connect():
            return False
            
        if not self.subscribe():
            return False
            
        if not self.authorize():
            return False
            
        # Start notification listener
        listener = threading.Thread(target=self.listen_notifications, daemon=True)
        listener.start()
        
        # Wait for initial setup
        time.sleep(2)
        
        print(f"🚀 Starting mining for {duration}s at {rate} shares/sec")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            self.submit_share()
            time.sleep(1.0 / rate)
            
        print(f"🏁 Mining complete!")
        print(f"📊 Stats: {self.share_count} shares, {len(self.difficulty_changes)} difficulty changes")
        
        for change in self.difficulty_changes:
            elapsed = change["time"] - start_time  
            print(f"  {elapsed:6.1f}s: {change['old']:6.2f} → {change['new']:6.2f} (after {change['shares']} shares)")
            
        return True

if __name__ == "__main__":
    print("🧪 Simple VARDIFF Test")
    print("=" * 30)
    
    miner = SimpleMiner()
    miner.mine(duration=60, rate=3.0)  # Fast mining to trigger VARDIFF
