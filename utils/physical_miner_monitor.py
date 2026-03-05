#!/usr/bin/env python3
"""
Physical Miner Real-time Monitor for C2Pool
Monitors active physical miner connections and Stratum activity
"""

import subprocess
import time
import socket
import json
import sys
from datetime import datetime

def get_physical_miner_connections():
    """Get detailed information about physical miner connections"""
    connections = []
    
    try:
        # Get network connections to port 8084
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            for line in lines:
                if ':8084' in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        # Extract remote IP (remove port)
                        remote_ip = remote_addr.split(':')[0]
                        connections.append({
                            'remote_ip': remote_ip,
                            'remote_addr': remote_addr,
                            'local_addr': local_addr
                        })
        
        # Get unique miners by IP
        unique_miners = {}
        for conn in connections:
            ip = conn['remote_ip']
            if ip not in unique_miners:
                unique_miners[ip] = {'ip': ip, 'connections': 0, 'ports': []}
            unique_miners[ip]['connections'] += 1
            port = conn['remote_addr'].split(':')[1]
            unique_miners[ip]['ports'].append(port)
        
        return list(unique_miners.values()), len(connections)
    
    except Exception as e:
        print(f"Error getting connections: {e}")
        return [], 0

def test_stratum_activity():
    """Test if the Stratum server is responsive"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("localhost", 8084))
        
        # Quick subscribe test
        subscribe_req = {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["monitor/1.0"]
        }
        
        message = json.dumps(subscribe_req) + "\n"
        sock.send(message.encode())
        
        sock.settimeout(2)
        response = sock.recv(1024).decode().strip()
        sock.close()
        
        # Parse response to check if it's valid
        if response and "result" in response:
            return True, "Active"
        else:
            return False, "No Response"
            
    except Exception as e:
        return False, str(e)

def monitor_physical_miners():
    """Real-time monitoring of physical miners"""
    print("🔋 C2Pool Physical Miner Real-time Monitor")
    print("==========================================")
    print("Press Ctrl+C to stop monitoring\n")
    
    start_time = datetime.now()
    check_count = 0
    
    try:
        while True:
            check_count += 1
            current_time = datetime.now()
            runtime = current_time - start_time
            
            # Get miner connections
            miners, total_connections = get_physical_miner_connections()
            
            # Test Stratum responsiveness
            stratum_ok, stratum_status = test_stratum_activity()
            
            # Clear screen and show header
            print(f"\033[2J\033[H", end="")  # Clear screen, move cursor to top
            print("🔋 C2Pool Physical Miner Real-time Monitor")
            print("==========================================")
            print(f"Runtime: {str(runtime).split('.')[0]} | Check: {check_count} | {current_time.strftime('%H:%M:%S')}")
            print(f"Stratum Server: {'🟢 Active' if stratum_ok else '🔴 ' + stratum_status}")
            print()
            
            if miners:
                print(f"👥 Physical Miners Connected: {len(miners)}")
                print(f"📡 Total Connections: {total_connections}")
                print("─" * 60)
                
                for i, miner in enumerate(miners, 1):
                    ports_str = ", ".join(miner['ports'][:3])  # Show first 3 ports
                    if len(miner['ports']) > 3:
                        ports_str += f" +{len(miner['ports'])-3} more"
                    
                    print(f"{i:2d}. 🖥️  {miner['ip']:<15} │ "
                          f"{miner['connections']:2d} conn │ "
                          f"Ports: {ports_str}")
                
                print()
                print("💡 Status: Physical miners are actively connected!")
                print("⚡ Miners should be receiving work and submitting shares")
                
            else:
                print("❌ No Physical Miners Connected")
                print("   • C2Pool is running and ready for connections")
                print("   • Miners should connect to: stratum+tcp://192.168.86.30:8084")
                print("   • Check miner configuration and network connectivity")
            
            print()
            print("Press Ctrl+C to stop monitoring...")
            
            # Wait before next check
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Monitoring stopped by user")
        print("📊 Final Summary:")
        print(f"   Runtime: {str(datetime.now() - start_time).split('.')[0]}")
        print(f"   Total checks: {check_count}")
        if miners:
            print(f"   Miners detected: {len(miners)}")
            print(f"   Total connections: {total_connections}")
        else:
            print("   No miners were connected during monitoring")

def quick_status():
    """Show a quick status check"""
    print("🔍 Quick Status Check")
    print("====================")
    
    miners, total_connections = get_physical_miner_connections()
    stratum_ok, stratum_status = test_stratum_activity()
    
    print(f"Stratum Server: {'✅ Active' if stratum_ok else '❌ ' + stratum_status}")
    print(f"Physical Miners: {len(miners)} unique miners")
    print(f"Total Connections: {total_connections}")
    
    if miners:
        print("\nConnected Miners:")
        for i, miner in enumerate(miners, 1):
            print(f"  {i}. {miner['ip']} ({miner['connections']} connections)")
    
    return len(miners) > 0

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        success = quick_status()
        sys.exit(0 if success else 1)
    else:
        monitor_physical_miners()

if __name__ == "__main__":
    main()
