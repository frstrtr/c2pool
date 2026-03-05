#!/usr/bin/env python3
"""
Comprehensive LTC Testnet Mining Test with Three Address Types
Tests legacy, SegWit, and bech32 addresses against C2Pool Stratum server
"""

import socket
import json
import time
import threading
import hashlib
import struct
import random
from datetime import datetime

class StratumMiner:
    def __init__(self, host, port, miner_id, worker_address, address_type):
        self.host = host
        self.port = port
        self.miner_id = miner_id
        self.worker_address = worker_address
        self.address_type = address_type
        self.sock = None
        self.subscribed = False
        self.authorized = False
        self.job = None
        self.running = False
        
    def connect(self):
        """Connect to Stratum server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)
            self.sock.connect((self.host, self.port))
            print(f"[{self.miner_id}] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[{self.miner_id}] Connection failed: {e}")
            return False
    
    def send_message(self, message):
        """Send JSON message to server"""
        try:
            msg_str = json.dumps(message) + '\\n'
            self.sock.send(msg_str.encode())
            return True
        except Exception as e:
            print(f"[{self.miner_id}] Send error: {e}")
            return False
    
    def receive_message(self):
        """Receive and parse JSON message"""
        try:
            data = self.sock.recv(1024).decode().strip()
            if data:
                for line in data.split('\\n'):
                    if line.strip():
                        return json.loads(line)
            return None
        except Exception as e:
            print(f"[{self.miner_id}] Receive error: {e}")
            return None
    
    def subscribe(self):
        """Subscribe to mining notifications"""
        subscribe_msg = {
            "id": 1,
            "method": "mining.subscribe",
            "params": [f"c2pool-miner-{self.miner_id}/1.0"]
        }
        
        if not self.send_message(subscribe_msg):
            return False
        
        response = self.receive_message()
        if response and response.get('id') == 1:
            if 'result' in response:
                print(f"[{self.miner_id}] ✅ Subscribed successfully")
                self.subscribed = True
                return True
            else:
                print(f"[{self.miner_id}] ❌ Subscribe failed: {response.get('error')}")
        
        return False
    
    def authorize(self):
        """Authorize with worker address"""
        auth_msg = {
            "id": 2,
            "method": "mining.authorize",
            "params": [self.worker_address, "password"]
        }
        
        print(f"[{self.miner_id}] Authorizing with {self.address_type} address: {self.worker_address}")
        
        if not self.send_message(auth_msg):
            return False
        
        response = self.receive_message()
        if response and response.get('id') == 2:
            if response.get('result') is True:
                print(f"[{self.miner_id}] ✅ Authorization SUCCESS - {self.address_type} address accepted!")
                self.authorized = True
                return True
            else:
                error_msg = response.get('error', {}).get('message', 'Unknown error')
                print(f"[{self.miner_id}] ❌ Authorization FAILED: {error_msg}")
                return False
        
        print(f"[{self.miner_id}] ❓ No authorization response")
        return False
    
    def simulate_mining(self, duration=30):
        """Simulate mining for a given duration"""
        if not (self.subscribed and self.authorized):
            print(f"[{self.miner_id}] Not ready for mining")
            return
        
        print(f"[{self.miner_id}] 🔨 Starting mining simulation for {duration} seconds")
        self.running = True
        start_time = time.time()
        share_count = 0
        
        try:
            while self.running and (time.time() - start_time) < duration:
                # Listen for job notifications
                self.sock.settimeout(1.0)
                try:
                    response = self.receive_message()
                    if response:
                        if response.get('method') == 'mining.notify':
                            self.job = response.get('params', [])
                            print(f"[{self.miner_id}] 📋 New job received")
                        elif response.get('method') == 'mining.set_difficulty':
                            difficulty = response.get('params', [1])[0]
                            print(f"[{self.miner_id}] ⚙️  Difficulty set to {difficulty}")
                except socket.timeout:
                    pass
                
                # Submit a fake share occasionally
                if random.random() < 0.1 and self.job:  # 10% chance
                    share_count += 1
                    fake_nonce = f"{random.randint(0, 0xFFFFFFFF):08x}"
                    submit_msg = {
                        "id": 100 + share_count,
                        "method": "mining.submit",
                        "params": [self.worker_address, self.job[0], "00000000", 
                                 str(int(time.time())), fake_nonce]
                    }
                    
                    if self.send_message(submit_msg):
                        print(f"[{self.miner_id}] 📤 Submitted mining share #{share_count}")
                
                time.sleep(2)  # Mining simulation delay
                
        except Exception as e:
            print(f"[{self.miner_id}] Mining error: {e}")
        
        print(f"[{self.miner_id}] 🏁 Mining completed. Shares submitted: {share_count}")
        self.running = False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.sock:
            try:
                self.sock.close()
                print(f"[{self.miner_id}] Disconnected")
            except:
                pass

def test_three_address_types():
    """Test all three LTC testnet address types"""
    
    # Our validated addresses
    test_miners = [
        {
            "id": "LEGACY",
            "address": "n4HFXoG2xEKFyzpGarucZzAd98seabNTPq",
            "type": "Legacy P2PKH"
        },
        {
            "id": "SEGWIT", 
            "address": "QNvFB4sd5fjN74hd77fVtWaCV1N2y1Kbmp",
            "type": "P2SH-SegWit"
        },
        {
            "id": "BECH32",
            "address": "tltc1qv6nx5p0gp8dxt9qsvz908ghlstmsf8833v36t2", 
            "type": "Native SegWit (bech32)"
        }
    ]
    
    print("🧪 LTC Testnet Mining Test - Three Address Formats")
    print("=" * 60)
    print(f"Testing at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target: localhost:8085 (C2Pool Stratum)")
    
    miners = []
    threads = []
    
    # Create miners
    for miner_config in test_miners:
        miner = StratumMiner(
            "127.0.0.1", 8085,  # Stratum port is 8085, not 8084
            miner_config["id"],
            miner_config["address"], 
            miner_config["type"]
        )
        miners.append(miner)
    
    # Test each miner
    results = []
    
    for miner in miners:
        print(f"\\n{'='*40}")
        print(f"🔍 Testing {miner.address_type}")
        print(f"Address: {miner.worker_address}")
        print(f"{'='*40}")
        
        # Connect and authorize
        if miner.connect():
            if miner.subscribe():
                if miner.authorize():
                    print(f"[{miner.miner_id}] ✅ Ready for mining!")
                    
                    # Start mining in a thread
                    mining_thread = threading.Thread(
                        target=miner.simulate_mining, 
                        args=(20,)  # 20 seconds of mining
                    )
                    mining_thread.start()
                    threads.append(mining_thread)
                    
                    results.append({
                        "id": miner.miner_id,
                        "type": miner.address_type,
                        "address": miner.worker_address,
                        "status": "SUCCESS"
                    })
                else:
                    results.append({
                        "id": miner.miner_id,
                        "type": miner.address_type, 
                        "address": miner.worker_address,
                        "status": "AUTH_FAILED"
                    })
            else:
                results.append({
                    "id": miner.miner_id,
                    "type": miner.address_type,
                    "address": miner.worker_address, 
                    "status": "SUBSCRIBE_FAILED"
                })
        else:
            results.append({
                "id": miner.miner_id,
                "type": miner.address_type,
                "address": miner.worker_address,
                "status": "CONNECTION_FAILED"
            })
    
    # Wait for all mining threads to complete
    for thread in threads:
        thread.join()
    
    # Disconnect all miners
    for miner in miners:
        miner.disconnect()
    
    # Print results
    print(f"\\n" + "=" * 60)
    print("📊 MINING TEST RESULTS")
    print("=" * 60)
    
    success_count = 0
    for result in results:
        status_icon = "✅" if result["status"] == "SUCCESS" else "❌"
        print(f"{status_icon} {result['type']:<20} {result['status']}")
        print(f"   Address: {result['address']}")
        
        if result["status"] == "SUCCESS":
            success_count += 1
    
    print(f"\\n📈 Summary: {success_count}/{len(results)} address types successful")
    
    if success_count == 3:
        print("🎉 ALL ADDRESS TYPES WORKING! C2Pool accepts:")
        print("   ✅ Legacy P2PKH addresses (n...)")
        print("   ✅ P2SH-SegWit addresses (Q... or 2...)")  
        print("   ✅ Native SegWit bech32 addresses (tltc1...)")
    elif success_count > 0:
        print(f"⚠️  Partial success: {success_count} address types working")
    else:
        print("❌ No address types working - check C2Pool server")
    
    return success_count == 3

if __name__ == "__main__":
    test_three_address_types()
