#!/usr/bin/env python3
"""
Monitor testnet mining activity and check for blocks
"""
import subprocess
import json
import time
import sys

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

def monitor_mining():
    """Monitor for new blocks and display mining info"""
    print("🔍 Monitoring Litecoin testnet mining activity...")
    print("Press Ctrl+C to stop\n")
    
    # Show recent blocks first
    show_recent_blocks(3)
    
    last_block_count = None
    
    try:
        while True:
            # Get current blockchain info
            info = run_litecoin_cli("getblockchaininfo")
            if not info:
                time.sleep(10)
                continue
                
            current_blocks = info['blocks']
            
            if last_block_count is None:
                last_block_count = current_blocks
                print(f"Current block height: {current_blocks}")
                print(f"Difficulty: {info['difficulty']:.2f}")
                print(f"Sync progress: {info['verificationprogress']*100:.2f}%")
                print("Waiting for new blocks...\n")
            elif current_blocks > last_block_count:
                # New block(s) found!
                for height in range(last_block_count + 1, current_blocks + 1):
                    block_hash = run_litecoin_cli(f"getblockhash {height}")
                    if block_hash:
                        block_details = check_block_details(block_hash)
                        if block_details:
                            # Highlight local pool blocks
                            if block_details['is_local_mine']:
                                print("🏆🎉 LOCAL POOL BLOCK MINED! 🎉🏆")
                                print("   *** WE FOUND A BLOCK! ***")
                            else:
                                print("🎉 NEW BLOCK MINED")
                            
                            print(f"   Height: {block_details['height']}")
                            print(f"   Time: {time.ctime(block_details['time'])}")
                            print(f"   Reward: {block_details['reward']} LTC")
                            print(f"   Miner Address: {block_details['miner']}")
                            print(f"   Miner Info: {block_details['miner_info']}")
                            print(f"   Difficulty: {block_details['difficulty']:.2f}")
                            print(f"   Transactions: {block_details['tx_count']}")
                            print(f"   Size: {block_details['size']:,} bytes")
                            print(f"   Hash: {block_details['hash']}")
                            
                            if block_details['is_local_mine']:
                                print("   💰 THIS BLOCK WAS MINED BY OUR POOL! 💰")
                                print("   ⭐ Congratulations! ⭐")
                            
                            print("   " + "="*50)
                            print()
                
                last_block_count = current_blocks
            
            # Check wallet for any mining rewards
            wallet_info = run_litecoin_cli("getwalletinfo")
            if wallet_info:
                if wallet_info['immature_balance'] > 0:
                    print(f"💰 Immature balance: {wallet_info['immature_balance']} LTC (coinbase maturing)")
                if wallet_info['balance'] > 0:
                    print(f"💎 Mature balance: {wallet_info['balance']} LTC")
            
            time.sleep(10)  # Check every 10 seconds
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    monitor_mining()
