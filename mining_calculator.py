#!/usr/bin/env python3
"""
Mining time calculator for Litecoin testnet
"""
import subprocess
import json
import time

def run_litecoin_cli(command):
    """Execute litecoin-cli command and return JSON result"""
    try:
        cmd = f"litecoin-cli -testnet {command}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return json.loads(result.stdout.strip())
        return None
    except:
        return None

def calculate_mining_time():
    """Calculate estimated time to mine a block with given hashrate"""
    
    # Get current network stats
    mining_info = run_litecoin_cli("getmininginfo")
    if not mining_info:
        print("Error: Could not get mining info")
        return
    
    current_difficulty = mining_info['difficulty']
    network_hashrate = mining_info['networkhashps']  # Hashes per second
    
    print("🔍 Current Litecoin Testnet Mining Stats:")
    print(f"   Difficulty: {current_difficulty:.2f}")
    print(f"   Network Hashrate: {network_hashrate/1e9:.2f} GH/s")
    print()
    
    # Antrouter L1-LTC specifications
    # Each Antrouter L1-LTC: ~1.3 MH/s (1.3 million hashes per second)
    antrouter_hashrate = 1.3e6  # 1.3 MH/s per unit
    num_antrouters = 3
    total_hashrate = antrouter_hashrate * num_antrouters
    
    print("🏭 Your Mining Setup:")
    print(f"   Miners: {num_antrouters} x Antrouter L1-LTC")
    print(f"   Hashrate per unit: {antrouter_hashrate/1e6:.1f} MH/s")
    print(f"   Total hashrate: {total_hashrate/1e6:.1f} MH/s ({total_hashrate/1e9:.6f} GH/s)")
    print()
    
    # Mining probability calculations
    # Probability of finding a block = your_hashrate / network_hashrate
    block_probability = total_hashrate / network_hashrate
    
    # Average time between Litecoin blocks is ~2.5 minutes (150 seconds)
    block_time_seconds = 150  # 2.5 minutes
    
    # Expected time to find a block = block_time / probability
    expected_time_seconds = block_time_seconds / block_probability
    
    print("⏰ Mining Time Estimates:")
    print(f"   Your share of network: {block_probability*100:.8f}%")
    print(f"   Average block time: {block_time_seconds/60:.1f} minutes")
    print()
    
    # Convert to human-readable time units
    minutes = expected_time_seconds / 60
    hours = minutes / 60
    days = hours / 24
    months = days / 30
    years = days / 365
    
    print("📊 Expected Time to Mine 1 Block:")
    if years >= 1:
        print(f"   {years:.1f} years ({days:.0f} days)")
    elif months >= 1:
        print(f"   {months:.1f} months ({days:.0f} days)")
    elif days >= 1:
        print(f"   {days:.1f} days ({hours:.0f} hours)")
    elif hours >= 1:
        print(f"   {hours:.1f} hours ({minutes:.0f} minutes)")
    else:
        print(f"   {minutes:.1f} minutes ({expected_time_seconds:.0f} seconds)")
    
    print()
    print("🎯 Statistical Probabilities:")
    print(f"   50% chance within: {expected_time_seconds * 0.693 / 3600:.1f} hours")
    print(f"   90% chance within: {expected_time_seconds * 2.303 / 3600:.1f} hours")
    print(f"   99% chance within: {expected_time_seconds * 4.605 / 3600:.1f} hours")
    
    # Difficulty vs mainnet comparison
    print()
    print("🔄 Network Comparison:")
    print(f"   Testnet difficulty: {current_difficulty:.2f}")
    print(f"   This is testnet - much easier than mainnet!")
    print(f"   Mainnet difficulty is typically 1000x+ higher")
    
    # Pool advantage
    print()
    print("🏊 Pool Mining Advantage:")
    print("   Solo mining: Very irregular payouts (long wait, then full block)")
    print("   Pool mining: Regular small payouts based on contributed work")
    print("   Your c2pool: Combines benefits of both approaches!")
    
    return {
        'difficulty': current_difficulty,
        'network_hashrate': network_hashrate,
        'your_hashrate': total_hashrate,
        'expected_time_seconds': expected_time_seconds,
        'expected_time_hours': hours,
        'expected_time_days': days,
        'block_probability': block_probability
    }

if __name__ == "__main__":
    print("⛏️  Litecoin Testnet Mining Calculator")
    print("="*50)
    print()
    
    stats = calculate_mining_time()
    
    if stats:
        print()
        print("💡 Tips:")
        print("   - These are statistical averages - actual time can vary greatly")
        print("   - You might find a block in minutes, or it might take much longer")
        print("   - Pool mining reduces variance and provides steadier income")
        print("   - Testnet is for testing - mainnet mining is much more competitive")
