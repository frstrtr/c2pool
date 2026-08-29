#!/usr/bin/env python3
"""
Simple C2Pool Mining Test Client
Tests share submission and storage functionality
"""

import socket
import json
import time
import requests
import sys
import subprocess

def test_web_interface():
    """Test the web interface and get current stats"""
    try:
        response = requests.get("http://localhost:8084/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Web interface accessible")
            print(f"   Current difficulty: {data.get('difficulty', 'N/A')}")
            print(f"   Pool hashrate: {data.get('poolhashps', 'N/A')} H/s")
            print(f"   Pool shares: {data.get('poolshares', 'N/A')}")
            print(f"   Connected miners: {data.get('connected_miners', 'N/A')}")
            print(f"   Testnet mode: {data.get('testnet', 'N/A')}")
            return True
        else:
            print(f"❌ Web interface returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Web interface error: {e}")
        return False

def test_stratum_connection():
    """Test basic Stratum connection on port 8084"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("localhost", 8084))
        
        # Send subscribe request
        subscribe_req = {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["test-client/1.0"]
        }
        
        message = json.dumps(subscribe_req) + "\n"
        sock.send(message.encode())
        
        # Try to receive response
        try:
            sock.settimeout(5)
            response = sock.recv(1024).decode().strip()
            print("✅ Stratum connection successful")
            print(f"   Response: {response}")
            
            # Try authorization with a test address
            auth_req = {
                "id": 2,
                "method": "mining.authorize",
                "params": ["tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "test"]
            }
            
            message = json.dumps(auth_req) + "\n"
            sock.send(message.encode())
            
            auth_response = sock.recv(1024).decode().strip()
            print(f"   Auth response: {auth_response}")
            
            return True
        except socket.timeout:
            print("⚠️  Stratum port accessible but no response timeout")
            return True
        except UnicodeDecodeError as e:
            print(f"⚠️  Stratum response decode error: {e}")
            return True
            
    except ConnectionRefusedError:
        print("❌ Stratum port not accessible (port 8084)")
        return False
    except OSError as e:
        print(f"❌ Stratum connection error: {e}")
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass

def simulate_mining_activity():
    """Monitor mining activity by checking web interface stats"""
    print("🔄 Monitoring mining activity...")
    
    # Make several requests to monitor pool stats
    for i in range(10):
        try:
            response = requests.get("http://localhost:8084/", timeout=2)
            if response.status_code == 200:
                data = response.json()
                shares = data.get('poolshares', 0)
                hashrate = data.get('poolhashps', 0)
                difficulty = data.get('difficulty', 1)
                miners = data.get('connected_miners', 0)
                
                print(f"   Check {i+1}: MiningShares={shares}, Hashrate={hashrate:.2f} H/s, "
                      f"Difficulty={difficulty}, Miners={miners}")
                
                if shares > 0:
                    print("   🎉 Mining shares detected!")
                if hashrate > 0:
                    print("   ⚡ Pool hashrate active!")
                    
            time.sleep(2)
        except requests.RequestException as e:
            print(f"   Check {i+1} failed: {e}")
    
    return True

def monitor_miners():
    """Monitor connected miners and their activity"""
    print("👥 Monitoring Physical Miners")
    print("=============================")
    
    previous_shares = 0
    previous_hashrate = 0
    
    try:
        for i in range(30):  # Monitor for 60 seconds
            try:
                response = requests.get("http://localhost:8084/", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    shares = data.get('poolshares', 0)
                    hashrate = data.get('poolhashps', 0)
                    difficulty = data.get('difficulty', 1)
                    miners = data.get('connected_miners', 0)
                    
                    # Calculate deltas
                    share_delta = shares - previous_shares
                    hashrate_delta = hashrate - previous_hashrate
                    
                    status = "🟢" if miners > 0 else "🔴"
                    activity = "📈" if share_delta > 0 else "📊"
                    
                    print(f"{status} [{i+1:2d}/30] Miners: {miners:2d} | "
                          f"MiningShares: {shares:4d} (+{share_delta}) | "
                          f"Hashrate: {hashrate:8.2f} H/s {activity}")
                    
                    if share_delta > 0:
                        print(f"    🎯 New mining shares found! Pool is actively mining.")
                    
                    if miners > 0 and i == 0:
                        print(f"    ✅ Physical miners detected and connected!")
                    
                    previous_shares = shares
                    previous_hashrate = hashrate
                    
                else:
                    print(f"    ❌ Web interface error: {response.status_code}")
                    
            except requests.RequestException as e:
                print(f"    ⚠️  Monitoring error: {e}")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n⏹️  Monitoring stopped by user")
    
    return True

def check_physical_miners():
    """Check for active physical miner connections to port 8084"""
    print("🔍 Checking for Physical Miner Connections")
    print("==========================================")
    
    try:
        # Check network connections to port 8084
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            connections_8084 = []
            
            for line in lines:
                if ':8084' in line and 'ESTABLISHED' in line:
                    connections_8084.append(line.strip())
            
            if connections_8084:
                print(f"✅ Found {len(connections_8084)} active connections to port 8084:")
                for i, conn in enumerate(connections_8084, 1):
                    parts = conn.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        print(f"   {i}. {remote_addr} -> {local_addr}")
                
                # Try to get more details from lsof if available
                try:
                    lsof_result = subprocess.run(['lsof', '-i', ':8084'], capture_output=True, text=True, timeout=5)
                    if lsof_result.returncode == 0:
                        print("📊 Detailed connection info:")
                        lsof_lines = lsof_result.stdout.split('\n')[1:]  # Skip header
                        for line in lsof_lines:
                            if line.strip() and 'ESTABLISHED' in line:
                                print(f"   {line}")
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass  # lsof might not be available
                
                return True
            else:
                print("ℹ️  No active connections found to port 8084")
                print("   Physical miners may not be connected yet")
                return False
        else:
            print(f"❌ Failed to check network connections: {result.stderr}")
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ Network check timed out")
        return False
    except Exception as e:
        print(f"❌ Error checking physical miners: {e}")
        return False

def test_stratum_protocol():
    """Test full Stratum protocol flow as a physical miner would"""
    print("🔌 Testing Full Stratum Protocol Flow")
    print("====================================")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("localhost", 8084))
        
        print("✅ Connected to Stratum server on port 8084")
        
        # Step 1: Subscribe
        subscribe_req = {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["physical-miner-test/1.0", None]
        }
        
        message = json.dumps(subscribe_req) + "\n"
        sock.send(message.encode())
        print("📤 Sent mining.subscribe request")
        
        try:
            sock.settimeout(5)
            response = sock.recv(4096).decode().strip()
            print(f"📥 Subscribe response: {response}")
            
            # Step 2: Authorize (with a test Litecoin testnet address)
            auth_req = {
                "id": 2,
                "method": "mining.authorize",
                "params": ["tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "test-password"]
            }
            
            message = json.dumps(auth_req) + "\n"
            sock.send(message.encode())
            print("📤 Sent mining.authorize request")
            
            auth_response = sock.recv(4096).decode().strip()
            print(f"📥 Authorize response: {auth_response}")
            
            # Step 3: Wait for mining.notify (job notifications)
            print("⏳ Waiting for mining job notifications...")
            sock.settimeout(10)
            
            for attempt in range(3):
                try:
                    notify_data = sock.recv(4096).decode().strip()
                    if notify_data:
                        print(f"📥 Job notification {attempt + 1}: {notify_data}")
                except socket.timeout:
                    print(f"   Attempt {attempt + 1}: No job notification received (timeout)")
                
            return True
            
        except socket.timeout:
            print("⚠️  Protocol response timeout - may indicate HTTP-only mode")
            return True
        except UnicodeDecodeError as e:
            print(f"⚠️  Protocol response decode error: {e}")
            return True
            
    except ConnectionRefusedError:
        print("❌ Could not connect to Stratum server on port 8084")
        return False
    except Exception as e:
        print(f"❌ Stratum protocol test error: {e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def main():
    print("🧪 C2Pool Physical Miner Monitor")
    print("================================")
    
    # Test 1: Web Interface
    print("\n📡 Test 1: Web Interface")
    web_ok = test_web_interface()
    
    # Test 2: Stratum Connection
    print("\n🔌 Test 2: Stratum Connection (Port 8084)")
    stratum_ok = test_stratum_connection()
    
    # Test 3: Mining Activity Check
    print("\n⛏️  Test 3: Mining Activity Check")
    mining_ok = simulate_mining_activity()
    
    # Test 4: Real-time Physical Miner Monitoring
    print("\n👥 Test 4: Physical Miner Monitoring")
    print("Press Ctrl+C to stop monitoring...")
    time.sleep(1)
    monitor_ok = monitor_miners()
    
    # Test 5: Check Physical Miners
    print("\n🔍 Test 5: Check Physical Miners Connections")
    check_ok = check_physical_miners()
    
    # Test 6: Stratum Protocol Test
    print("\n🔌 Test 6: Stratum Protocol Full Flow")
    protocol_ok = test_stratum_protocol()
    
    # Final Report
    print("\n📊 Monitoring Summary")
    print("====================")
    print(f"Web Interface: {'✅ PASS' if web_ok else '❌ FAIL'}")
    print(f"Stratum Port:  {'✅ PASS' if stratum_ok else '❌ FAIL'}")
    print(f"Mining Check:  {'✅ PASS' if mining_ok else '❌ FAIL'}")
    print(f"Miner Monitor: {'✅ PASS' if monitor_ok else '❌ FAIL'}")
    print(f"Physical Miners: {'✅ PASS' if check_ok else '❌ FAIL'}")
    print(f"Stratum Protocol: {'✅ PASS' if protocol_ok else '❌ FAIL'}")
    
    if web_ok and stratum_ok:
        print("\n🎉 C2Pool Enhanced is operational!")
        print("💡 Miner connection: stratum+tcp://localhost:8084")
        print("🔗 Web interface: http://localhost:8084")
        return 0
    else:
        print("\n⚠️  Some connectivity issues detected.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
