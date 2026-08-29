#!/usr/bin/env python3
"""
C2Pool Enhanced Share Type Monitor
Demonstrates the new separation between mining_shares and p2p_shares
"""

import socket
import json
import time
import requests
import sys
import subprocess
from datetime import datetime

def monitor_share_types():
    """Monitor and display different share types separately"""
    print("🔄 C2Pool Enhanced Share Type Monitor")
    print("=====================================")
    print("Monitoring separation between:")
    print("  🖥️  Mining Shares - From physical miners via Stratum")
    print("  🌐 P2P Shares - From cross-node communication")
    print("  📡 Total Activity - Combined statistics")
    print()
    
    start_time = datetime.now()
    check_count = 0
    
    try:
        while True:
            check_count += 1
            current_time = datetime.now()
            runtime = current_time - start_time
            
            # Get connection info for physical miners
            miners, total_connections = get_physical_miner_connections()
            
            # Get pool statistics
            try:
                response = requests.get("http://localhost:8084/", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Display enhanced statistics with new terminology
                    print(f"\033[2J\033[H", end="")  # Clear screen
                    print("🔄 C2Pool Enhanced Share Type Monitor")
                    print("=====================================")
                    print(f"Runtime: {str(runtime).split('.')[0]} | Check: {check_count} | {current_time.strftime('%H:%M:%S')}")
                    print()
                    
                    # Mining Shares Section (from physical miners)
                    print("🖥️  MINING SHARES (Physical Miners)")
                    print("─" * 40)
                    mining_shares = data.get('poolshares', 0)  # These are from miners
                    mining_hashrate = data.get('poolhashps', 0)
                    mining_difficulty = data.get('difficulty', 1)
                    connected_miners = len(miners)
                    
                    print(f"   Connected Miners: {connected_miners}")
                    print(f"   Total Connections: {total_connections}")
                    print(f"   Mining Shares: {mining_shares}")
                    print(f"   Mining Hashrate: {mining_hashrate:.2f} H/s")
                    print(f"   Current Difficulty: {mining_difficulty}")
                    
                    if miners:
                        print("   Active Miner IPs:")
                        for i, miner in enumerate(miners[:3], 1):  # Show first 3
                            print(f"     {i}. {miner['ip']} ({miner['connections']} conn)")
                        if len(miners) > 3:
                            print(f"     ... and {len(miners) - 3} more")
                    
                    print()
                    
                    # P2P Shares Section (from cross-node communication)
                    print("🌐 P2P SHARES (Cross-Node Communication)")
                    print("─" * 40)
                    # These would come from peer connections and sharechain sync
                    p2p_peers = data.get('connected_peers', 0)
                    p2p_shares = data.get('p2p_shares_received', 0)  # Hypothetical field
                    p2p_verified = data.get('p2p_shares_verified', 0)  # Hypothetical field
                    
                    print(f"   Connected Peers: {p2p_peers}")
                    print(f"   P2P Shares Received: {p2p_shares}")
                    print(f"   P2P Shares Verified: {p2p_verified}")
                    print(f"   Verification Rate: {(p2p_verified/max(p2p_shares,1)*100):.1f}%")
                    print("   Active Networks: LTC, BTC (simulated)")
                    
                    print()
                    
                    # Combined Statistics
                    print("📡 TOTAL ACTIVITY (Combined)")
                    print("─" * 40)
                    total_shares = mining_shares + p2p_shares
                    print(f"   Total Shares: {total_shares}")
                    print(f"     ├─ Mining: {mining_shares} ({(mining_shares/max(total_shares,1)*100):.1f}%)")
                    print(f"     └─ P2P: {p2p_shares} ({(p2p_shares/max(total_shares,1)*100):.1f}%)")
                    print(f"   Network Health: {'🟢 Good' if connected_miners > 0 and p2p_peers > 0 else '🟡 Limited'}")
                    
                    print()
                    print("Press Ctrl+C to stop monitoring...")
                    
                else:
                    print(f"❌ Web interface error: {response.status_code}")
                    
            except requests.RequestException as e:
                print(f"⚠️  Monitoring error: {e}")
            
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Monitoring stopped by user")
        print("📊 Final Summary:")
        print(f"   Runtime: {str(datetime.now() - start_time).split('.')[0]}")
        print(f"   Total checks: {check_count}")
        print("   Share type separation successfully demonstrated!")

def get_physical_miner_connections():
    """Get detailed information about physical miner connections (same as before)"""
    connections = []
    
    try:
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            for line in lines:
                if ':8084' in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        remote_addr = parts[4]
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

def demo_share_separation():
    """Demonstrate the conceptual separation of share types"""
    print("📋 C2Pool Enhanced Share Type Separation")
    print("========================================")
    print()
    print("🎯 NEW NAMING CONVENTION:")
    print()
    print("🖥️  MINING SHARES:")
    print("   ├─ Source: Physical mining hardware")
    print("   ├─ Protocol: Stratum (port 8084)")
    print("   ├─ Purpose: Proof of work from miners")
    print("   ├─ Tracking: Hashrate, difficulty, VARDIFF")
    print("   └─ Examples: ASIC miners, GPU rigs")
    print()
    print("🌐 P2P SHARES:")
    print("   ├─ Source: Other C2Pool/P2Pool nodes")
    print("   ├─ Protocol: P2Pool network protocol")
    print("   ├─ Purpose: Sharechain synchronization")
    print("   ├─ Tracking: Verification, forwarding, peers")
    print("   └─ Examples: Cross-node communication")
    print()
    print("📊 BENEFITS:")
    print("   ├─ Clear separation of concerns")
    print("   ├─ Better debugging and monitoring")
    print("   ├─ Optimized tracking per type")
    print("   ├─ Enhanced statistics and reporting")
    print("   └─ Improved network analysis")
    print()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_share_separation()
    elif len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        monitor_share_types()
    else:
        demo_share_separation()
        print("\nUsage:")
        print("  python3 share_type_monitor.py --demo     # Show conceptual separation")
        print("  python3 share_type_monitor.py --monitor  # Real-time monitoring")

if __name__ == "__main__":
    main()
