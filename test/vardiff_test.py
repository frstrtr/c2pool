#!/usr/bin/env python3
"""
VARDIFF Test Script for C2Pool
Tests the variable difficulty adjustment system by connecting multiple miners
and monitoring difficulty changes in real-time.
"""

import socket
import json
import time
import threading
import logging
from typing import Dict, Any
import hashlib
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class VardiffTestMiner:
    """Simulated miner that connects via Stratum and monitors difficulty changes"""
    
    def __init__(self, miner_id: str, address: str, port: int, payout_address: str, submission_rate: float = 2.0):
        self.miner_id = miner_id
        self.address = address
        self.port = port
        self.payout_address = payout_address
        self.submission_rate = submission_rate  # submissions per second
        self.socket = None
        self.connected = False
        self.subscribed = False
        self.authorized = False
        self.current_difficulty = 1.0
        self.difficulty_history = []
        self.share_count = 0
        self.logger = logging.getLogger(f"Miner-{miner_id}")
        
    def connect(self):
        """Connect to the Stratum server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.address, self.port))
            self.connected = True
            self.logger.info(f"Connected to {self.address}:{self.port}")
            return True
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def send_request(self, method: str, params: list, req_id: int = None) -> Dict[str, Any]:
        """Send a JSON-RPC request and get response"""
        if req_id is None:
            req_id = int(time.time() * 1000) % 1000000
            
        request = {
            "id": req_id,
            "method": method,
            "params": params
        }
        
        message = json.dumps(request) + "\n"
        self.socket.send(message.encode())
        
        # Wait for response with the same ID
        while True:
            response_line = ""
            while True:
                data = self.socket.recv(1024).decode()
                response_line += data
                if "\n" in response_line:
                    break
                    
            lines = response_line.strip().split('\n')
            for line in lines:
                if line:
                    try:
                        response = json.loads(line)
                        # Check if this is the response to our request
                        if "id" in response and response["id"] == req_id:
                            return response
                        else:
                            # This is a notification, handle it
                            self.handle_notification(response)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Invalid JSON response: {line}")
                        continue
    
    def subscribe(self):
        """Subscribe to mining notifications"""
        response = self.send_request("mining.subscribe", [f"VardiffTestMiner/{self.miner_id}"])
        if "result" in response and response["result"]:
            self.subscribed = True
            self.logger.info("Successfully subscribed")
            return True
        else:
            self.logger.error(f"Subscription failed: {response}")
            return False
    
    def authorize(self):
        """Authorize with payout address"""
        response = self.send_request("mining.authorize", [self.payout_address, "password"])
        if "result" in response and response["result"]:
            self.authorized = True
            self.logger.info(f"Successfully authorized with address: {self.payout_address}")
            return True
        else:
            self.logger.error(f"Authorization failed: {response}")
            return False
    
    def listen_for_notifications(self):
        """Listen for mining.set_difficulty and mining.notify messages"""
        while self.connected:
            try:
                # Set a shorter timeout for listening
                self.socket.settimeout(1.0)
                data = self.socket.recv(1024).decode()
                
                if not data:
                    break
                    
                for line in data.strip().split('\n'):
                    if line:
                        try:
                            message = json.loads(line)
                            self.handle_notification(message)
                        except json.JSONDecodeError:
                            continue
                            
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error in notification listener: {e}")
                break
    
    def handle_notification(self, message: Dict[str, Any]):
        """Handle incoming notifications from server"""
        if "method" in message:
            method = message["method"]
            params = message.get("params", [])
            
            if method == "mining.set_difficulty":
                old_difficulty = self.current_difficulty
                self.current_difficulty = params[0] if params else 1.0
                self.difficulty_history.append({
                    "timestamp": time.time(),
                    "difficulty": self.current_difficulty,
                    "share_count": self.share_count
                })
                self.logger.info(f"🎯 DIFFICULTY CHANGE: {old_difficulty:.2f} → {self.current_difficulty:.2f} "
                               f"(shares submitted: {self.share_count})")
                
            elif method == "mining.notify":
                self.logger.debug("Received work notification")
    
    def generate_share_submission(self) -> tuple:
        """Generate pseudo-random share submission parameters"""
        job_id = f"job_{int(time.time())}"
        extranonce2 = f"{random.randint(0, 0xFFFFFFFF):08x}"
        ntime = f"{int(time.time()):08x}"
        nonce = f"{random.randint(0, 0xFFFFFFFF):08x}"
        
        return job_id, extranonce2, ntime, nonce
    
    def submit_share(self):
        """Submit a mining share"""
        if not self.authorized:
            return False
            
        job_id, extranonce2, ntime, nonce = self.generate_share_submission()
        
        response = self.send_request("mining.submit", [
            self.payout_address, job_id, extranonce2, ntime, nonce
        ])
        
        if "result" in response and response["result"]:
            self.share_count += 1
            self.logger.info(f"✅ Share #{self.share_count} accepted (difficulty: {self.current_difficulty:.2f})")
            return True
        else:
            self.logger.warning(f"❌ Share rejected: {response}")
            return False
    
    def mine(self, duration: int = 300):
        """Start mining for the specified duration"""
        if not self.connect():
            return False
            
        if not self.subscribe():
            return False
            
        if not self.authorize():
            return False
        
        # Start notification listener in background
        listener_thread = threading.Thread(target=self.listen_for_notifications, daemon=True)
        listener_thread.start()
        
        start_time = time.time()
        self.logger.info(f"🚀 Starting mining for {duration} seconds at rate {self.submission_rate:.1f} shares/sec")
        
        while time.time() - start_time < duration and self.connected:
            try:
                self.submit_share()
                time.sleep(1.0 / self.submission_rate)
            except Exception as e:
                self.logger.error(f"Error during mining: {e}")
                break
        
        self.logger.info(f"🏁 Mining completed. Total shares: {self.share_count}, "
                        f"Difficulty changes: {len(self.difficulty_history)}")
        
        # Print difficulty history
        if self.difficulty_history:
            self.logger.info("📊 DIFFICULTY HISTORY:")
            for entry in self.difficulty_history:
                elapsed = entry["timestamp"] - start_time
                self.logger.info(f"  {elapsed:6.1f}s: {entry['difficulty']:8.2f} "
                               f"(after {entry['share_count']} shares)")
        
        return True
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            self.connected = False


def test_vardiff_system():
    """Test the VARDIFF system with multiple miners"""
    
    # LTC testnet addresses for different miners (valid ones)
    test_addresses = [
        "tltc1qrqxtj6u4x3xd3jjk4xe8gp8fv2z6pvkl5ld6z5",  # Bech32 SegWit
        "tltc1qw8wrek2m7nlqldll66ajnwr9vanqtddz7kqjvz",  # Bech32 SegWit
        "tltc1qvzwdjefhdw5e5n5dqk6z35tujxz8p8zjk3uc6e"   # Bech32 SegWit
    ]
    
    # Create miners with different submission rates to test VARDIFF
    miners = [
        VardiffTestMiner("FastMiner", "localhost", 8084, test_addresses[0], submission_rate=3.0),
        VardiffTestMiner("MediumMiner", "localhost", 8084, test_addresses[1], submission_rate=1.5),
        VardiffTestMiner("SlowMiner", "localhost", 8084, test_addresses[2], submission_rate=0.8),
    ]
    
    print("🧪 VARDIFF SYSTEM TEST")
    print("=" * 50)
    print("This test will connect multiple simulated miners with different hashrates")
    print("and monitor how the VARDIFF system adjusts difficulty per miner.")
    print()
    
    # Start miners in separate threads
    threads = []
    for miner in miners:
        thread = threading.Thread(target=lambda m=miner: m.mine(180), daemon=True)  # 3 minutes
        threads.append(thread)
        thread.start()
        time.sleep(2)  # Stagger the starts
    
    # Wait for all miners to complete
    for thread in threads:
        thread.join()
    
    print("\n📈 VARDIFF TEST RESULTS")
    print("=" * 50)
    
    for miner in miners:
        print(f"\n{miner.miner_id} ({miner.payout_address}):")
        print(f"  Shares submitted: {miner.share_count}")
        print(f"  Final difficulty: {miner.current_difficulty:.2f}")
        print(f"  Difficulty adjustments: {len(miner.difficulty_history)}")
        
        if miner.difficulty_history:
            initial_diff = 1.0
            final_diff = miner.current_difficulty
            print(f"  Difficulty change: {initial_diff:.2f} → {final_diff:.2f} "
                 f"({final_diff/initial_diff:.1f}x)")
        
        miner.disconnect()


if __name__ == "__main__":
    test_vardiff_system()
