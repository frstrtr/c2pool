#!/usr/bin/env python3
"""
Test fixtures providing mock API responses for c2pool Qt control panel

Used for:
- Offline testing (UI development without daemon)
- Smoke testing (validation of all endpoints)
- Integration testing (daemon vs Qt)
"""

import json
import datetime
import time
from typing import Dict, Any, List

class MockApiFixtures:
    """Provides realistic mock data matching daemon endpoint specs"""
    
    @staticmethod
    def uptime() -> int:
        """GET /uptime - daemon uptime in seconds"""
        return 3600 + int(time.time() % 3600)
    
    @staticmethod
    def global_stats() -> Dict[str, Any]:
        """GET /global_stats - comprehensive node statistics"""
        return {
            "pool_hashrate": 142.5e12,  # 142.5 TH/s
            "network_hashrate": 8.2e18,  # 8.2 EH/s
            "pool_stale_ratio": 0.023,
            "shares_in_chain": 8542,
            "unique_miners": 47,
            "current_height": 4823156,
            "uptime_seconds": MockApiFixtures.uptime(),
            "status": "operational",
            "last_block": int(time.time()) - 420
        }
    
    @staticmethod
    def connected_miners() -> Dict[str, Any]:
        """GET /connected_miners - active miner sessions"""
        return {
            "total_connected": 127,
            "active_workers": 342,
            "stale_count": 8
        }
    
    @staticmethod
    def stratum_stats() -> Dict[str, Any]:
        """GET /stratum_stats - stratum protocol statistics"""
        return {
            "difficulty": 4.2,
            "accepted_shares": 15342,
            "rejected_shares": 128,
            "stale_shares": 42,
            "hashrate": 125.3e12,
            "active_workers": 342,
            "unique_addresses": 47,
            "shares_per_minute": 12.5,
            "last_share_time": int(time.time())
        }
    
    @staticmethod
    def sharechain_stats() -> Dict[str, Any]:
        """GET /sharechain/stats - sharechain structure and distribution"""
        now = int(time.time())
        
        # Build timeline data (6 slots, 10 minutes each going back)
        timeline = []
        for i in range(6):
            slot_time = now - (i * 600)
            timeline.insert(0, {
                "timestamp": slot_time,
                "share_count": 10 + (i * 5),  # Increasing distribution
                "miner_distribution": {
                    "ltc1q1234567890abcdef": (i+1)*2,
                    "ltc1qabcdefghijklmnop": (i+1)*3,
                    "ltc1qxyz9999999999999": i+1
                }
            })
        
        return {
            "total_shares": 8542,
            "shares_by_version": {
                "36": 5123,
                "35": 2841,
                "34": 578
            },
            "shares_by_miner": {
                "ltc1q1234567890abcdef": 1823,
                "ltc1qabcdefghijklmnop": 3412,
                "ltc1qxyz9999999999999": 1247,
                "ltc1qotherminer000000": 2060
            },
            "chain_height": 8542,
            "chain_tip_hash": "0x123abc...def123",
            "fork_count": 3,
            "heaviest_fork_weight": 0.87,
            "average_difficulty": 2.1,
            "difficulty_trend": [1.8, 1.9, 2.0, 2.1, 2.1, 2.2],
            "timeline": timeline
        }
    
    @staticmethod
    def recent_blocks() -> List[Dict[str, Any]]:
        """GET /recent_blocks - recently found blocks"""
        now = int(time.time())
        return [
            {
                "height": 4823156,
                "hash": "000000000fc1b7dc1234567890abcdef1234567890abcdef1234567890abc",
                "ts": now - 3600
            },
            {
                "height": 4823155,
                "hash": "000000000fc1b7dcfedcba0987654321fedcba0987654321fedcba0987654",
                "ts": now - 7200
            }
        ]
    
    @staticmethod
    def logs_export(scope: str = "all", num_lines: int = 100) -> str:
        """GET /logs/export - exported logs in text format"""
        logs = []
        now = datetime.datetime.now()
        
        for i in range(num_lines):
            ts = (now - datetime.timedelta(seconds=num_lines - i)).isoformat()
            
            if scope in ["all", "node"]:
                logs.append(f"[{ts}] [INFO ] [node] Miner connected: ltc1q{i:040x}")
            
            if scope in ["all", "stratum"]:
                logs.append(f"[{ts}] [DEBUG] [stratum] Processing share #{i} from worker_{i%20}")
            
            if scope in ["all", "security"]:
                if i % 15 == 0:
                    logs.append(f"[{ts}] [WARN ] [security] Possible DDoS: 50 connections/sec from {i}.{i}.{i}.{i}")
        
        return "\n".join(logs)
    
    @staticmethod
    def validate_all() -> bool:
        """Validate all fixtures return dict/list/str/int correctly"""
        try:
            assert isinstance(MockApiFixtures.uptime(), int)
            assert isinstance(MockApiFixtures.global_stats(), dict)
            assert isinstance(MockApiFixtures.connected_miners(), dict)
            assert isinstance(MockApiFixtures.stratum_stats(), dict)
            assert isinstance(MockApiFixtures.sharechain_stats(), dict)
            assert isinstance(MockApiFixtures.recent_blocks(), list)
            assert isinstance(MockApiFixtures.logs_export(), str)
            return True
        except AssertionError:
            return False


class MockApiServer:
    """Simple in-process mock API server for offline testing"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.endpoints = {
            "/uptime": lambda: MockApiFixtures.uptime(),
            "/global_stats": lambda: MockApiFixtures.global_stats(),
            "/connected_miners": lambda: MockApiFixtures.connected_miners(),
            "/stratum_stats": lambda: MockApiFixtures.stratum_stats(),
            "/sharechain/stats": lambda: MockApiFixtures.sharechain_stats(),
            "/recent_blocks": lambda: MockApiFixtures.recent_blocks(),
        }
    
    def get_response(self, path: str) -> str:
        """Get response for endpoint path"""
        if path in self.endpoints:
            result = self.endpoints[path]()
            if isinstance(result,(dict, list)):
                return json.dumps(result)
            elif isinstance(result, str):
                return result
            else:
                return str(result)
        return json.dumps({"error": "endpoint not found"})


if __name__ == "__main__":
    # Validate fixtures
    print("Validating fixtures...")
    if MockApiFixtures.validate_all():
        print("✓ All fixtures validated successfully")
        
        # Pretty-print sharechain stats
        print("\nSharechain Stats Sample:")
        print(json.dumps(MockApiFixtures.sharechain_stats(), indent=2))
        
        # Show logs export
        print("\nLogs Export Sample (first 500 chars):")
        logs = MockApiFixtures.logs_export("all", 20)
        print(logs[:500] + "...")
    else:
        print("✗ Fixture validation failed")
        exit(1)
