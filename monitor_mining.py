#!/usr/bin/env python3
"""
Monitor testnet mining activity and check for blocks
"""
import subprocess
import json
import time
import sys
import os
import urllib.request
import urllib.error

def run_litecoin_cli(command):
    """Execute litecoin-cli command and return JSON result"""
    try:
        cmd = f"litecoin-cli -testnet {command}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout.strip()
            if not output:
                return None
            # Handle simple string returns (like block hashes)
            if command.startswith('getblockhash') or command.startswith('getbestblockhash'):
                return output  # Return string directly for hashes
            # Parse JSON for other commands
            return json.loads(output)
        else:
            print(f"Error: {result.stderr.strip()}")
            return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error for command '{command}': {e}")
        return None
    except Exception as e:
        print(f"Command failed: {e}")
        return None

def get_local_addresses():
    """Get all addresses from the local wallet"""
    try:
        # Get all addresses from the wallet
        addresses = set()
        
        # Get receiving addresses
        receiving = run_litecoin_cli("listreceivedbyaddress 0 true")
        if receiving:
            for addr_info in receiving:
                addresses.add(addr_info.get('address', ''))
        
        # Get all wallet addresses
        wallet_addresses = run_litecoin_cli("getaddressesbylabel \"\"")
        if wallet_addresses:
            addresses.update(wallet_addresses.keys())
            
        return addresses
    except:
        return set()

def check_block_details(block_hash):
    """Get details about a specific block"""
    block = run_litecoin_cli(f"getblock {block_hash}")
    if not block:
        return None
    
    # Get coinbase transaction details
    coinbase_txid = block['tx'][0]  # First transaction is always coinbase
    local_addresses = get_local_addresses()
    
    try:
        coinbase = run_litecoin_cli(f"getrawtransaction {coinbase_txid} true {block_hash}")
        if coinbase and coinbase['vout']:
            reward = coinbase['vout'][0]['value']
            script_pub_key = coinbase['vout'][0]['scriptPubKey']
            
            # Extract miner address and check if it's ours
            miner_address = 'Unknown'
            is_local_mine = False
            
            if 'addresses' in script_pub_key and script_pub_key['addresses']:
                miner_address = script_pub_key['addresses'][0]
                is_local_mine = miner_address in local_addresses
            elif 'address' in script_pub_key:
                miner_address = script_pub_key['address']
                is_local_mine = miner_address in local_addresses
            
            # Extract miner info from coinbase data
            miner_info = "Unknown"
            if 'coinbase' in coinbase['vin'][0]:
                coinbase_data = coinbase['vin'][0]['coinbase']
                try:
                    # Try to decode readable text from coinbase
                    decoded = bytes.fromhex(coinbase_data).decode('utf-8', errors='ignore')
                    # Look for common miner signatures
                    if 'c2pool' in decoded.lower():
                        miner_info = "c2pool"
                        is_local_mine = True
                    elif any(x in decoded for x in ['CyberLeap', 'Antminer', 'BTC.com', 'F2Pool', 'ViaBTC']):
                        # Extract recognizable miner names
                        for name in ['CyberLeap', 'Antminer', 'BTC.com', 'F2Pool', 'ViaBTC']:
                            if name in decoded:
                                miner_info = name
                                break
                except:
                    pass
            
            return {
                'height': block['height'],
                'time': block['time'],
                'difficulty': block['difficulty'],
                'reward': reward,
                'miner': miner_address,
                'miner_info': miner_info,
                'hash': block_hash,
                'is_local_mine': is_local_mine,
                'tx_count': block.get('nTx', 0),
                'size': block.get('size', 0),
                'confirmations': block.get('confirmations', 0)
            }
    except Exception as e:
        print(f"Error processing block {block_hash}: {e}")
        pass
    
    return None

def show_recent_blocks(count=5):
    """Show details of the most recent blocks"""
    print(f"📊 Recent {count} blocks:")
    print("="*60)
    
    current_height = run_litecoin_cli("getblockcount")
    if not current_height:
        print("Error getting current block height")
        return
    
    for i in range(count):
        height = current_height - i
        if height < 0:
            break
            
        block_hash = run_litecoin_cli(f"getblockhash {height}")
        if block_hash:
            block_details = check_block_details(block_hash)
            if block_details:
                status = "🏆 LOCAL POOL" if block_details['is_local_mine'] else "🌐 External"
                print(f"Block {block_details['height']} - {status}")
                print(f"  Time: {time.ctime(block_details['time'])}")
                print(f"  Miner: {block_details['miner_info']} ({block_details['miner'][:20]}...)")
                print(f"  Reward: {block_details['reward']} LTC")
                print(f"  TXs: {block_details['tx_count']}, Size: {block_details['size']:,} bytes")
                print()

def get_stratum_connections():
    """Get information about miners connected to Stratum server on port 8084"""
    try:
        # Check network connections to port 8084 to see active miner connections
        result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            connections = []
            unique_ips = set()  # Track unique IP addresses
            lines = result.stdout.split('\n')
            
            for line in lines:
                # Look for ESTABLISHED connections TO port 8084 (incoming connections)
                if ':8084 ' in line and 'ESTABLISHED' in line:
                    # Make sure it's an incoming connection (local address has :8084)
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        
                        # Only count if our local address is listening on 8084
                        if ':8084' in local_addr:
                            # Extract just the IP address (remove port)
                            remote_ip = remote_addr.split(':')[0]
                            
                            # Filter out localhost/loopback connections
                            if (remote_ip not in ['127.0.0.1', '::1', 'localhost'] and 
                                not remote_ip.startswith('127.') and
                                remote_ip != '0.0.0.0'):
                                
                                # Add to unique IPs set
                                unique_ips.add(remote_ip)
                                
                                # Store connection details
                                connections.append({
                                    'local': local_addr,
                                    'remote': remote_addr,
                                    'remote_ip': remote_ip,
                                    'status': 'ESTABLISHED'
                                })
            
            # Group connections by IP to show connection count per miner
            ip_connections = {}
            for conn in connections:
                ip = conn['remote_ip']
                if ip not in ip_connections:
                    ip_connections[ip] = []
                ip_connections[ip].append(conn)
            
            return {
                'active_connections': len(connections),  # Total connections
                'unique_miners': len(unique_ips),        # Unique miner count
                'connections': connections,
                'miners_by_ip': ip_connections,
                'stratum_accessible': True
            }
    except Exception:
        pass
    
    # Check if port 8084 is listening at all
    try:
        result = subprocess.run(['netstat', '-tln'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            listening = False
            for line in result.stdout.split('\n'):
                if ':8084 ' in line and 'LISTEN' in line:
                    listening = True
                    break
            
            return {
                'active_connections': 0,
                'unique_miners': 0,
                'connections': [],
                'miners_by_ip': {},
                'stratum_accessible': True,
                'port_listening': listening
            }
    except Exception:
        pass
    
    return None

def detect_testnet_mode():
    """Detect if c2pool is running in testnet mode by checking process arguments"""
    try:
        # Check c2pool process arguments
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'c2pool' in line and '--testnet' in line:
                    return True
                    
        # Also check litecoind process as backup
        for line in result.stdout.split('\n'):
            if 'litecoind' in line and '-testnet' in line:
                return True
                
    except Exception:
        pass
    
    return False

def get_c2pool_miners():
    """Get information about miners connected to c2pool"""
    # Get Stratum server connection info (port 8084)
    stratum_info = get_stratum_connections()
    
    # Get pool web interface info (port 8083) for additional stats
    pool_web_info = None
    try:
        url = "http://localhost:8083/"
        with urllib.request.urlopen(url, timeout=3) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                pool_web_info = {
                    'pool_hashrate': data.get('poolhashps', 0),
                    'pool_difficulty': data.get('difficulty', 0),
                    'pool_version': data.get('version', 'Unknown'),
                    'testnet_mode': detect_testnet_mode(),  # Use process detection instead of web interface
                    'pool_blocks': data.get('blocks', 0),
                    'web_connections': data.get('connections', 0)  # This might be different from Stratum
                }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, ConnectionError):
        pass
    
    # Combine information
    if stratum_info or pool_web_info:
        result = {
            'miners': [],  # Individual miner data not available without custom Stratum protocol
            'pool_accessible': True
        }
        
        # Prioritize Stratum connection count over web interface count
        if stratum_info:
            result.update({
                'connected_count': stratum_info['unique_miners'],     # Use unique miners count
                'total_connections': stratum_info['active_connections'], # Total TCP connections
                'connections': stratum_info['connections'],
                'miners_by_ip': stratum_info.get('miners_by_ip', {}),
                'port_listening': stratum_info.get('port_listening', True)
            })
        else:
            result['connected_count'] = 0
            result['total_connections'] = 0
            result['port_listening'] = False
        
        # Add web interface stats if available
        if pool_web_info:
            result.update(pool_web_info)
        else:
            # Ensure testnet detection works even without web interface
            result['testnet_mode'] = detect_testnet_mode()
        
        return result
    
    return None

def get_pool_stats():
    """Get general pool statistics from c2pool"""
    try:
        url = "http://localhost:8083/stats"
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return {
                    'pool_hashrate': data.get('pool_hashrate', 0),
                    'connected_miners': data.get('connected_miners', 0),
                    'pool_blocks': data.get('blocks_found', 0),
                    'pool_efficiency': data.get('efficiency', 0),
                    'uptime': data.get('uptime', 0)
                }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, ConnectionError):
        pass
    
    return None

def get_hashrate_info():
    """Get network and local hashrate information"""
    mining_info = run_litecoin_cli("getmininginfo")
    if not mining_info:
        return None
    
    network_hashrate = mining_info.get('networkhashps', 0)
    difficulty = mining_info.get('difficulty', 0)
    
    # Try to get actual pool hashrate from c2pool
    pool_stats = get_pool_stats()
    if pool_stats and pool_stats['pool_hashrate'] > 0:
        local_hashrate_estimate = pool_stats['pool_hashrate']
    else:
        # Fallback estimate for 3x Antrouter L1-LTC
        local_hashrate_estimate = 3.9e6  # 3.9 MH/s for 3 Antrouters
    
    return {
        'network_hashrate': network_hashrate,
        'network_hashrate_gh': network_hashrate / 1e9,
        'difficulty': difficulty,
        'local_hashrate': local_hashrate_estimate,
        'local_hashrate_mh': local_hashrate_estimate / 1e6,
        'network_share': (local_hashrate_estimate / network_hashrate * 100) if network_hashrate > 0 else 0,
        'estimated_time_hours': (150 / (local_hashrate_estimate / network_hashrate)) / 3600 if network_hashrate > 0 else 0
    }

def clear_screen():
    """Clear the terminal screen"""
    print("\033[2J", end="")

def move_cursor(row, col):
    """Move cursor to specific position (1-indexed)"""
    print(f"\033[{row};{col}H", end="")

def clear_line():
    """Clear current line"""
    print("\033[K", end="")

def hide_cursor():
    """Hide the cursor"""
    print("\033[?25l", end="")

def show_cursor():
    """Show the cursor"""
    print("\033[?25h", end="")

def format_hashrate(hashrate):
    """Format hashrate with appropriate units"""
    if hashrate >= 1e12:
        return f"{hashrate/1e12:.2f} TH/s"
    elif hashrate >= 1e9:
        return f"{hashrate/1e9:.2f} GH/s"
    elif hashrate >= 1e6:
        return f"{hashrate/1e6:.2f} MH/s"
    elif hashrate >= 1e3:
        return f"{hashrate/1e3:.2f} KH/s"
    else:
        return f"{hashrate:.0f} H/s"

def get_terminal_size():
    """Get terminal size"""
    try:
        import shutil
        return shutil.get_terminal_size()
    except:
        return (80, 24)  # Default fallback

def draw_interface(current_blocks, hashrate_info, blocks_found, wallet_info, last_block_info=None, miner_info=None):
    """Draw the complete monitoring interface"""
    # Get terminal size to prevent scrolling
    term_size = get_terminal_size()
    max_lines = term_size.lines - 2  # Leave some margin
    
    clear_screen()
    move_cursor(1, 1)
    
    lines_used = 0
    
    # Header
    print("🔍 Litecoin Testnet Mining Monitor - c2pool on Stratum :8084")
    print("=" * min(80, term_size.columns - 1))
    print()
    lines_used += 3
    
    # Current status table
    print("📊 CURRENT STATUS")
    print("-" * 40)
    print(f"Block Height:     {current_blocks}")
    lines_used += 3
    
    if hashrate_info:
        print(f"Network HashRate: {format_hashrate(hashrate_info['network_hashrate'])}")
        print(f"Pool HashRate:    {format_hashrate(hashrate_info['local_hashrate'])}")
        print(f"Network Share:    {hashrate_info['network_share']:.6f}%")
        print(f"Difficulty:       {hashrate_info['difficulty']:.2f}")
        print(f"Est. Time:        {hashrate_info['estimated_time_hours']:.1f} hours")
        lines_used += 5
    print()
    lines_used += 1
    
    # Miner information section - only if we have space
    if miner_info and lines_used < max_lines - 15:
        print("⛏️  C2POOL & STRATUM STATUS")
        print("-" * 40)
        lines_used += 2
        
        # Show key information compactly
        if 'pool_version' in miner_info:
            version = miner_info['pool_version']
            mode = "Testnet" if miner_info.get('testnet_mode', False) else "Mainnet"
            print(f"Pool: {version} ({mode}) - Online ✓")
            lines_used += 1
        
        # Show Stratum server status
        if 'port_listening' in miner_info:
            if miner_info['port_listening']:
                print("Stratum: Listening on port 8084 ✓")
            else:
                print("Stratum: ❌ Not listening on port 8084")
            lines_used += 1
        
        # Show actual miner connections (unique IPs)
        connected = miner_info.get('connected_count', 0)
        total_conn = miner_info.get('total_connections', 0)
        
        if connected > 0:
            if total_conn > connected:
                print(f"Active Miners: {connected} ({total_conn} connections)")
            else:
                print(f"Active Miners: {connected}")
        else:
            print(f"Active Miners: {connected}")
        lines_used += 1
        
        # Show individual miners by IP if any and we have space
        if connected > 0 and 'miners_by_ip' in miner_info and lines_used < max_lines - 8:
            miners_by_ip = miner_info['miners_by_ip']
            for i, (ip, connections) in enumerate(list(miners_by_ip.items())[:3], 1):  # Show max 3
                conn_count = len(connections)
                if conn_count > 1:
                    print(f"  {i}. {ip} ({conn_count} connections)")
                else:
                    print(f"  {i}. {ip}")
                lines_used += 1
            
            if len(miners_by_ip) > 3:
                print(f"  ... +{len(miners_by_ip) - 3} more miners")
                lines_used += 1
        
        # Show pool hashrate
        pool_hashrate = miner_info.get('pool_hashrate', 0)
        if pool_hashrate > 0:
            print(f"Pool Hashrate: {format_hashrate(pool_hashrate)}")
        else:
            print("Pool Hashrate: 0 H/s")
        lines_used += 1
        
        print()
        lines_used += 1
    
    elif not miner_info and lines_used < max_lines - 5:
        print("⛏️  C2POOL CONNECTION")
        print("-" * 40)
        print("Status: ❌ Unable to connect")
        print()
        lines_used += 4
    
    # Latest block info - only if we have space
    if lines_used < max_lines - 8:
        print("🎉 LATEST BLOCK")
        print("-" * 40)
        if last_block_info:
            status = "🏆 LOCAL" if last_block_info['is_local_mine'] else "🌐 External"
            print(f"#{last_block_info['height']} - {status} - {last_block_info['miner_info']}")
            print(f"{time.strftime('%H:%M:%S', time.localtime(last_block_info['time']))}")
        else:
            print("Waiting for first block...")
        print()
        lines_used += 5
    
    # Session statistics - compact version if we have space
    if blocks_found and lines_used < max_lines - 6:
        local_count = sum(1 for b in blocks_found if b['is_local'])
        external_count = len(blocks_found) - local_count
        print(f"📈 SESSION: {len(blocks_found)} blocks ({local_count} local, {external_count} external)")
        
        # Show only last 3 blocks if we have space
        if lines_used < max_lines - 4:
            recent = blocks_found[-3:] if len(blocks_found) > 3 else blocks_found
            for block in recent:
                status = "LOCAL" if block['is_local'] else "Ext"
                miner = block['miner_info'][:8]
                time_str = time.strftime('%H:%M', time.localtime(block['time']))
                print(f"  {block['height']} | {status} | {miner} | {time_str}")
                lines_used += 1
        print()
        lines_used += 2
    
    # Wallet status - only if we have balances and space
    if wallet_info and lines_used < max_lines - 3:
        if wallet_info.get('immature_balance', 0) > 0 or wallet_info.get('balance', 0) > 0:
            print("💰 WALLET")
            if wallet_info.get('immature_balance', 0) > 0:
                print(f"Immature: {wallet_info['immature_balance']} LTC")
            if wallet_info.get('balance', 0) > 0:
                print(f"Balance: {wallet_info['balance']} LTC")
            print()
    
    # Make sure we stay within terminal bounds
    if lines_used < max_lines - 1:
        print("Press Ctrl+C to stop...")
    
    sys.stdout.flush()

def monitor_mining():
    """Monitor for new blocks and display mining info with full screen control"""
    hide_cursor()
    
    try:
        # Initialize tracking variables
        last_block_count = None
        last_update_time = time.time()
        blocks_found = []  # List of block dictionaries
        last_block_info = None
        
        # Initial display
        clear_screen()
        print("🔍 Initializing Litecoin testnet monitoring...")
        print("Connecting to daemon and gathering initial data...\n")
        
        while True:
            # Get current blockchain info
            info = run_litecoin_cli("getblockchaininfo")
            if not info:
                time.sleep(5)
                continue
                
            current_blocks = info['blocks']
            hashrate_info = get_hashrate_info()
            wallet_info = run_litecoin_cli("getwalletinfo")
            miner_info = get_c2pool_miners()  # Get connected miner information
            
            # Initialize on first run
            if last_block_count is None:
                last_block_count = current_blocks
                # Get info about current block for initial display
                block_hash = run_litecoin_cli(f"getblockhash {current_blocks}")
                if block_hash:
                    last_block_info = check_block_details(block_hash)
            
            # Check for new blocks
            elif current_blocks > last_block_count:
                for height in range(last_block_count + 1, current_blocks + 1):
                    block_hash = run_litecoin_cli(f"getblockhash {height}")
                    if block_hash:
                        block_details = check_block_details(block_hash)
                        if block_details:
                            # Add to persistent list
                            blocks_found.append({
                                'height': block_details['height'],
                                'time': block_details['time'],
                                'miner_info': block_details['miner_info'],
                                'is_local': block_details['is_local_mine'],
                                'reward': block_details['reward']
                            })
                            
                            last_block_info = block_details
                            
                            # If it's a local pool block, show celebration
                            if block_details['is_local_mine']:
                                show_cursor()
                                clear_screen()
                                print("🏆🎉🎉🎉 LOCAL POOL BLOCK MINED! 🎉🎉🎉🏆")
                                print("=" * 60)
                                print("   *** WE FOUND A BLOCK! ***")
                                print(f"   Height: {block_details['height']}")
                                print(f"   Time: {time.ctime(block_details['time'])}")
                                print(f"   Reward: {block_details['reward']} LTC")
                                print(f"   Miner Address: {block_details['miner']}")
                                print(f"   Miner Info: {block_details['miner_info']}")
                                print(f"   Difficulty: {block_details['difficulty']:.2f}")
                                print(f"   Transactions: {block_details['tx_count']}")
                                print(f"   Size: {block_details['size']:,} bytes")
                                print(f"   Hash: {block_details['hash']}")
                                if hashrate_info:
                                    print(f"   Network Hashrate: {format_hashrate(hashrate_info['network_hashrate'])}")
                                    print(f"   Your Share: {hashrate_info['network_share']:.6f}% of network")
                                print("   💰 THIS BLOCK WAS MINED BY OUR POOL! 💰")
                                print("   ⭐ Congratulations! ⭐")
                                print("=" * 60)
                                print("\nPress Enter to return to monitoring...")
                                input()  # Wait for user input
                                hide_cursor()
                
                last_block_count = current_blocks
            
            # Update display every second, or immediately after block changes
            current_time = time.time()
            if (current_time - last_update_time) >= 1.0:  # Update every second
                draw_interface(current_blocks, hashrate_info, blocks_found, wallet_info, last_block_info, miner_info)
                last_update_time = current_time
            
            time.sleep(1)  # Check every second for responsive updates
            
    except KeyboardInterrupt:
        show_cursor()
        clear_screen()
        print("Monitoring stopped.")
        
        # Show final summary
        if blocks_found:
            local_count = sum(1 for b in blocks_found if b['is_local'])
            external_count = len(blocks_found) - local_count
            print(f"\n📊 Final Session Summary:")
            print(f"Total blocks found: {len(blocks_found)}")
            print(f"Local pool blocks: {local_count}")
            print(f"External blocks: {external_count}")
            if local_count > 0:
                total_rewards = sum(b['reward'] for b in blocks_found if b['is_local'])
                print(f"Total rewards earned: {total_rewards} LTC")
    
    except Exception as e:
        show_cursor()
        clear_screen()
        print(f"Error occurred: {e}")
    
    finally:
        show_cursor()

if __name__ == "__main__":
    monitor_mining()
