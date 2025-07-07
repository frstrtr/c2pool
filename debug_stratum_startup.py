#!/usr/bin/env python3
"""
Debug script to check C2Pool Stratum startup
"""

import subprocess
import time
import json

def run_litecoin_cli(command):
    """Run a litecoin-cli command and return the result"""
    try:
        result = subprocess.run(['litecoin-cli', '-testnet'] + command.split(), 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"❌ litecoin-cli error: {result.stderr}")
            return None
    except Exception as e:
        print(f"❌ Exception running litecoin-cli: {e}")
        return None

def check_blockchain_sync():
    """Check if the blockchain is properly synced"""
    print("🔗 Checking Litecoin Core blockchain sync status...")
    
    # Test basic connectivity
    network_info = run_litecoin_cli("getnetworkinfo")
    if not network_info:
        print("❌ Cannot connect to Litecoin Core")
        return False
    
    print("✅ Connected to Litecoin Core")
    
    # Check blockchain info
    blockchain_info = run_litecoin_cli("getblockchaininfo")
    if not blockchain_info:
        print("❌ Cannot get blockchain info")
        return False
    
    try:
        info = json.loads(blockchain_info)
        
        blocks = info.get('blocks', 0)
        headers = info.get('headers', 0)
        progress = info.get('verificationprogress', 0.0)
        initial_download = info.get('initialblockdownload', True)
        
        print(f"📊 Blockchain Status:")
        print(f"   Blocks: {blocks}")
        print(f"   Headers: {headers}")
        print(f"   Progress: {progress:.6f}")
        print(f"   Initial Block Download: {initial_download}")
        
        # Same logic as C2Pool
        is_synced = (not initial_download and 
                    progress > 0.999 and 
                    (headers - blocks) <= 2)
        
        if is_synced:
            print("✅ Blockchain is synced")
            return True
        else:
            print("❌ Blockchain is not considered synced")
            return False
            
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse blockchain info: {e}")
        return False

def start_c2pool():
    """Start C2Pool and monitor its output"""
    print("\n🚀 Starting C2Pool...")
    
    try:
        # Start C2Pool as a background process
        proc = subprocess.Popen([
            './build/src/c2pool/c2pool',
            '--testnet',
            '--integrated', '0.0.0.0:8084',
            '--blockchain', 'ltc'
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
           text=True, bufsize=1, universal_newlines=True)
        
        print("⏳ Waiting for C2Pool startup (checking logs for 15 seconds)...")
        
        stratum_started = False
        web_started = False
        
        start_time = time.time()
        while time.time() - start_time < 15:
            line = proc.stdout.readline()
            if line:
                line = line.strip()
                print(f"📝 {line}")
                
                if "Web server listening" in line:
                    web_started = True
                    print("✅ Web server started")
                
                if "Stratum server listening" in line:
                    stratum_started = True
                    print("✅ Stratum server started")
                
                if "Stratum server will start once blockchain is synchronized" in line:
                    print("⚠️  Stratum server waiting for blockchain sync")
                
                if "Failed to start Stratum server" in line:
                    print("❌ Stratum server failed to start")
            
            # Check if process terminated
            if proc.poll() is not None:
                print("❌ C2Pool process terminated")
                break
                
            time.sleep(0.1)
        
        print(f"\n📊 Startup Summary:")
        print(f"   Web Server: {'✅ Started' if web_started else '❌ Not started'}")
        print(f"   Stratum Server: {'✅ Started' if stratum_started else '❌ Not started'}")
        
        # Try to connect to Stratum if it should be running
        if stratum_started:
            test_stratum_connection()
        
        # Clean up
        print("\n🛑 Stopping C2Pool...")
        proc.terminate()
        proc.wait(timeout=5)
        
        return stratum_started
        
    except Exception as e:
        print(f"❌ Error starting C2Pool: {e}")
        return False

def test_stratum_connection():
    """Test connection to Stratum server"""
    print("\n🧪 Testing Stratum connection...")
    
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", 8085))
        print("✅ Connected to Stratum server")
        sock.close()
    except Exception as e:
        print(f"❌ Failed to connect to Stratum server: {e}")

def main():
    print("🔍 C2Pool Stratum Startup Debug Tool")
    print("=" * 50)
    
    # Step 1: Check blockchain sync
    if not check_blockchain_sync():
        print("\n❌ Blockchain sync check failed. Stratum won't start.")
        return
    
    # Step 2: Start C2Pool and monitor
    success = start_c2pool()
    
    if success:
        print("\n✅ Stratum server started successfully!")
    else:
        print("\n❌ Stratum server did not start")

if __name__ == "__main__":
    main()
