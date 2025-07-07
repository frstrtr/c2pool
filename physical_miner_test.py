#!/usr/bin/env python3
"""
Physical Miner Simulator for C2Pool Litecoin Testnet Testing
Simulates real mining hardware connecting via Stratum protocol to port 8084
"""

import socket
import json
import time
import threading
import hashlib
import random
import argparse
import struct
from datetime import datetime

class StratumMiner:
    def __init__(self, host, port, miner_id, worker_name="worker1"):
        self.host = host
        self.port = port
        self.miner_id = miner_id
        # Use valid Litecoin testnet addresses from the test validation file
        ltc_testnet_addresses = [
            "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0",  # Native SegWit
            "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",            # P2SH (wrapped SegWit) 
            "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR",               # Legacy P2PKH
            "tltc1qg42g5wql6x09v5s0tg4j8klrhfw0zhtxsnzmmy",   # Additional bech32
            "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc"             # Additional P2SH
        ]
        self.worker_name = ltc_testnet_addresses[miner_id % len(ltc_testnet_addresses)]
        self.socket = None
        self.connected = False
        self.authorized = False
        self.session_id = None
        self.difficulty = 1.0
        self.job = None
        self.extranonce1 = None
        self.extranonce2_size = 4
        
        # Mining statistics
        self.shares_submitted = 0
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.start_time = time.time()
        
        # Simulated mining parameters
        self.hashrate = random.uniform(10, 100)  # MH/s
        self.mining_active = False
        
    def connect(self):
        """Connect to the Stratum server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"[{self.miner_id}] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[{self.miner_id}] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        self.mining_active = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        print(f"[{self.miner_id}] Disconnected")
    
    def send_message(self, method, params=None, msg_id=None):
        """Send a JSON-RPC message"""
        if not self.connected or not self.socket:
            return False
        
        if msg_id is None:
            msg_id = random.randint(1, 1000000)
        
        message = {
            "id": msg_id,
            "method": method,
            "params": params or []
        }
        
        try:
            data = json.dumps(message) + '\n'
            self.socket.send(data.encode('utf-8'))
            print(f"[{self.miner_id}] Sent: {method}")
            return True
        except Exception as e:
            print(f"[{self.miner_id}] Send error: {e}")
            return False
    
    def receive_message(self):
        """Receive a JSON-RPC message"""
        if not self.connected or not self.socket:
            return None
        
        try:
            data = b''
            while b'\n' not in data:
                chunk = self.socket.recv(1024)
                if not chunk:
                    return None
                data += chunk
            
            message = data.decode('utf-8').strip()
            if message:
                return json.loads(message)
        except Exception as e:
            print(f"[{self.miner_id}] Receive error: {e}")
        
        return None
    
    def subscribe(self):
        """Send mining.subscribe"""
        user_agent = f"MiningSimulator/{self.miner_id}"
        return self.send_message("mining.subscribe", [user_agent])
    
    def authorize(self, username, password="x"):
        """Send mining.authorize"""
        return self.send_message("mining.authorize", [username, password])
    
    def submit_share(self, job_id, extranonce2, ntime, nonce):
        """Submit a mining share"""
        params = [
            f"{self.miner_id}.{self.worker_name}",  # worker name
            job_id,                                 # job id
            extranonce2,                           # extranonce2
            ntime,                                 # ntime
            nonce                                  # nonce
        ]
        
        return self.send_message("mining.submit", params)
    
    def generate_share(self):
        """Generate a simulated mining share"""
        if not self.job:
            return None
        
        # Simulate mining work
        extranonce2 = f"{random.randint(0, 0xffffffff):08x}"
        ntime = f"{int(time.time()):08x}"
        nonce = f"{random.randint(0, 0xffffffff):08x}"
        
        # Simple difficulty check simulation
        # In real mining, this would involve actual hashing
        share_difficulty = random.uniform(0.5, self.difficulty * 2)
        
        return {
            'job_id': self.job['job_id'],
            'extranonce2': extranonce2,
            'ntime': ntime,
            'nonce': nonce,
            'difficulty': share_difficulty
        }
    
    def mining_loop(self):
        """Main mining simulation loop"""
        print(f"[{self.miner_id}] Starting mining loop (simulated {self.hashrate:.1f} MH/s)")
        
        while self.mining_active and self.connected:
            if self.job and self.authorized:
                # Simulate time to find a share based on difficulty and hashrate
                time_to_share = self.difficulty / (self.hashrate * 1e6) * random.uniform(0.5, 2.0)
                time.sleep(min(time_to_share, 10))  # Max 10 seconds between shares
                
                if not self.mining_active:
                    break
                
                # Generate and submit share
                share = self.generate_share()
                if share:
                    self.submit_share(
                        share['job_id'],
                        share['extranonce2'], 
                        share['ntime'],
                        share['nonce']
                    )
                    self.shares_submitted += 1
                    print(f"[{self.miner_id}] Submitted mining_share #{self.shares_submitted} "
                          f"(job: {share['job_id'][:8]}, nonce: {share['nonce']})")
            else:
                time.sleep(1)
    
    def handle_responses(self):
        """Handle server responses"""
        while self.connected:
            response = self.receive_message()
            if not response:
                continue
            
            # Handle different message types
            if 'method' in response:
                # Notification from server
                method = response['method']
                params = response.get('params', [])
                
                if method == "mining.notify":
                    # New job notification
                    self.job = {
                        'job_id': params[0],
                        'prev_hash': params[1],
                        'coinb1': params[2],
                        'coinb2': params[3],
                        'merkle_branches': params[4],
                        'version': params[5],
                        'nbits': params[6],
                        'ntime': params[7],
                        'clean_jobs': params[8]
                    }
                    print(f"[{self.miner_id}] New job: {self.job['job_id']}")
                
                elif method == "mining.set_difficulty":
                    # Difficulty change
                    self.difficulty = params[0]
                    print(f"[{self.miner_id}] Difficulty changed to: {self.difficulty}")
                
                elif method == "mining.set_extranonce":
                    # Extranonce change (reconnect case)
                    self.extranonce1 = params[0]
                    self.extranonce2_size = params[1]
                    print(f"[{self.miner_id}] Extranonce updated: {self.extranonce1}")
            
            elif 'result' in response:
                # Response to our request
                msg_id = response.get('id')
                result = response.get('result')
                error = response.get('error')
                
                if error:
                    print(f"[{self.miner_id}] Error response: {error}")
                    if "submit" in str(error):
                        self.shares_rejected += 1
                else:
                    if isinstance(result, list) and len(result) >= 2:
                        # mining.subscribe response
                        self.session_id = result[1]
                        if len(result) >= 3:
                            self.extranonce1 = result[1]
                            self.extranonce2_size = result[2]
                        print(f"[{self.miner_id}] Subscribed: {self.session_id}")
                    
                    elif isinstance(result, bool):
                        if result:
                            if not self.authorized:
                                self.authorized = True
                                print(f"[{self.miner_id}] Authorized successfully")
                            else:
                                # Share accepted
                                self.shares_accepted += 1
                                acceptance_rate = (self.shares_accepted / max(1, self.shares_submitted)) * 100
                                print(f"[{self.miner_id}] MINING_SHARE ACCEPTED! "
                                      f"({self.shares_accepted}/{self.shares_submitted}, "
                                      f"{acceptance_rate:.1f}% acceptance rate)")
                        else:
                            self.shares_rejected += 1
                            print(f"[{self.miner_id}] Share rejected")
    
    def get_stats(self):
        """Get mining statistics"""
        runtime = time.time() - self.start_time
        hashrate = (self.shares_submitted * self.difficulty) / max(1, runtime) * (1e6 / 1e6)  # Approximate
        
        return {
            'miner_id': self.miner_id,
            'connected': self.connected,
            'authorized': self.authorized,
            'difficulty': self.difficulty,
            'shares_submitted': self.shares_submitted,
            'shares_accepted': self.shares_accepted,
            'shares_rejected': self.shares_rejected,
            'acceptance_rate': (self.shares_accepted / max(1, self.shares_submitted)) * 100,
            'runtime': runtime,
            'estimated_hashrate': self.hashrate
        }
    
    def run(self):
        """Main miner run loop"""
        if not self.connect():
            return False
        
        # Start response handler
        response_thread = threading.Thread(target=self.handle_responses, daemon=True)
        response_thread.start()
        
        # Subscribe to mining
        if not self.subscribe():
            self.disconnect()
            return False
        
        time.sleep(1)
        
        # Authorize with the Litecoin testnet address
        username = self.worker_name  # Use the valid Litecoin address
        if not self.authorize(username):
            self.disconnect()
            return False
        
        time.sleep(1)
        
        # Start mining
        self.mining_active = True
        mining_thread = threading.Thread(target=self.mining_loop, daemon=True)
        mining_thread.start()
        
        return True

def run_miner_pool(host, port, num_miners, duration):
    """Run multiple miners for testing"""
    print(f"Starting {num_miners} simulated miners against {host}:{port}")
    print(f"Test duration: {duration} seconds")
    print("=" * 60)
    
    miners = []
    
    # Start miners
    for i in range(num_miners):
        miner_id = i + 1  # Use integer for array indexing
        miner = StratumMiner(host, port, miner_id)
        miners.append(miner)
        
        if miner.run():
            print(f"✅ miner_{miner_id:02d} started successfully")
            time.sleep(0.5)  # Stagger connections
        else:
            print(f"❌ miner_{miner_id:02d} failed to start")
    
    # Run for specified duration
    try:
        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(10)
            
            # Print statistics
            print(f"\n📊 Mining Statistics ({time.time() - start_time:.0f}s elapsed):")
            print("-" * 60)
            
            total_submitted = 0
            total_accepted = 0
            active_miners = 0
            
            for miner in miners:
                if miner.connected:
                    active_miners += 1
                    stats = miner.get_stats()
                    total_submitted += stats['shares_submitted']
                    total_accepted += stats['shares_accepted']
                    
                    print(f"{stats['miner_id']}: "
                          f"{stats['shares_accepted']}/{stats['shares_submitted']} "
                          f"({stats['acceptance_rate']:.1f}%) "
                          f"diff={stats['difficulty']:.3f} "
                          f"hr={stats['estimated_hashrate']:.1f}MH/s")
            
            overall_rate = (total_accepted / max(1, total_submitted)) * 100
            print(f"\n🏆 Overall: {total_accepted}/{total_submitted} "
                  f"({overall_rate:.1f}% acceptance rate, {active_miners} active miners)")
    
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    
    finally:
        # Cleanup
        print("\n🔄 Shutting down miners...")
        for miner in miners:
            miner.disconnect()
        
        print("✅ Test completed!")

def main():
    parser = argparse.ArgumentParser(description='C2Pool Stratum Miner Simulator')
    parser.add_argument('--host', default='localhost', help='C2Pool host (default: localhost)')
    parser.add_argument('--port', type=int, default=8084, help='Stratum port (default: 8084)')
    parser.add_argument('--miners', type=int, default=5, help='Number of miners (default: 5)')
    parser.add_argument('--duration', type=int, default=300, help='Test duration in seconds (default: 300)')
    parser.add_argument('--single', action='store_true', help='Run single miner interactively')
    
    args = parser.parse_args()
    
    if args.single:
        # Run single miner interactively
        print(f"🔧 Starting single miner test against {args.host}:{args.port}")
        miner = StratumMiner(args.host, args.port, "test_miner")
        
        if miner.run():
            try:
                while True:
                    time.sleep(5)
                    stats = miner.get_stats()
                    print(f"📊 Stats: {stats['shares_accepted']}/{stats['shares_submitted']} "
                          f"({stats['acceptance_rate']:.1f}%) diff={stats['difficulty']:.3f}")
            except KeyboardInterrupt:
                print("\n⏹️  Stopping miner...")
                miner.disconnect()
    else:
        # Run miner pool test
        run_miner_pool(args.host, args.port, args.miners, args.duration)

if __name__ == "__main__":
    main()
