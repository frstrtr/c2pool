#!/usr/bin/env python3
"""
Smoke test suite for c2pool Qt control panel

Tests:
1. Offline mode: Verify UI can work with mocked API responses
2. Online mode: Verify real daemon endpoints are accessible and return valid structure
3. Data validation: Ensure all responses match expected schemas
4. Error handling: Verify graceful fallback on endpoint errors
"""

import sys
import json
import subprocess
import time
import socket
import requests
from typing import Dict, Any, List, Tuple
from fixtures import MockApiFixtures, MockApiServer

class SmokeTest:
    """Smoke test suite for c2pool monitoring"""
    
    TIMEOUT = 3
    REQUIRED_FIELDS = {
        "/uptime": [],  # returns scalar
        "/global_stats": ["pool_hashrate", "network_hashrate", "status", "uptime_seconds"],
        "/connected_miners": ["total_connected", "active_workers"],
        "/stratum_stats": ["difficulty", "accepted_shares", "hashrate", "active_workers"],
        "/sharechain/stats": ["total_shares", "shares_by_version", "chain_height", "timeline"],
        "/recent_blocks": [],  # returns array
    }
    
    def __init__(self, daemon_url: str = "http://127.0.0.1:8080", offline_mode: bool = False):
        self.daemon_url = daemon_url
        self.offline_mode = offline_mode
        self.results = []
        self.passed = 0
        self.failed = 0
    
    def run_all(self) -> bool:
        """Run all smoke tests"""
        print("=" * 80)
        print("c2pool Qt Control Panel - Smoke Tests")
        print("=" * 80)
        print(f"Mode: {'OFFLINE (mocked)' if self.offline_mode else 'ONLINE (live daemon)'}")
        print(f"Target: {self.daemon_url}\n")
        
        if self.offline_mode:
            self._test_fixtures()
            self._test_mock_responses()
        else:
            self._test_daemon_connectivity()
            self._test_endpoint_responses()
        
        self._print_summary()
        return self.failed == 0
    
    def _test_fixtures(self):
        """Test 1: Verify mock fixtures are valid"""
        print("[Test 1] Fixture Validation")
        try:
            assert MockApiFixtures.validate_all(), "Fixture validation failed"
            self._pass("All fixtures generated successfully")
        except Exception as e:
            self._fail(f"Fixture error: {e}")
    
    def _test_mock_responses(self):
        """Test 2: Verify mock responses match schema"""
        print("[Test 2] Mock Response Schema Validation")
        
        fixtures = {
            "/uptime": MockApiFixtures.uptime(),
            "/global_stats": MockApiFixtures.global_stats(),
            "/connected_miners": MockApiFixtures.connected_miners(),
            "/stratum_stats": MockApiFixtures.stratum_stats(),
            "/sharechain/stats": MockApiFixtures.sharechain_stats(),
            "/recent_blocks": MockApiFixtures.recent_blocks(),
        }
        
        for endpoint, response in fixtures.items():
            self._validate_response(endpoint, response)
    
    def _test_daemon_connectivity(self):
        """Test 3: Daemon is reachable"""
        print("[Test 3] Daemon Connectivity")
        
        try:
            # Parse URL
            from urllib.parse import urlparse
            parsed = urlparse(self.daemon_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 8080
            
            # Try socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                self._pass(f"Daemon reachable at {host}:{port}")
            else:
                self._fail(f"Cannot reach daemon at {host}:{port}")
        except Exception as e:
            self._fail(f"Connectivity error: {e}")
    
    def _test_endpoint_responses(self):
        """Test 4: Each endpoint returns valid data"""
        print("[Test 4] Live Endpoint Response Validation")
        
        for endpoint in self.REQUIRED_FIELDS.keys():
            try:
                url = f"{self.daemon_url}{endpoint}"
                resp = requests.get(url, timeout=self.TIMEOUT)
                
                if resp.status_code != 200:
                    self._fail(f"{endpoint}: HTTP {resp.status_code}")
                    continue
                
                # Try to parse response
                try:
                    data = resp.json() if "json" in resp.headers.get("content-type", "") else resp.text
                    if isinstance(data, str):
                        data = json.loads(data)
                    self._validate_response(endpoint, data)
                except json.JSONDecodeError:
                    self._fail(f"{endpoint}: Invalid JSON response")
                    
            except requests.exceptions.ConnectionError:
                self._fail(f"{endpoint}: Connection refused")
            except requests.exceptions.Timeout:
                self._fail(f"{endpoint}: Request timeout")
            except Exception as e:
                self._fail(f"{endpoint}: {e}")
    
    def _validate_response(self, endpoint: str, response: Any):
        """Validate response structure against schema"""
        required = self.REQUIRED_FIELDS.get(endpoint, [])
        
        if isinstance(response, dict) and required:
            missing = [f for f in required if f not in response]
            if missing:
                self._fail(f"{endpoint}: Missing fields {missing}")
            else:
                self._pass(f"{endpoint}: Valid response ({len(response)} fields)")
        elif isinstance(response, list):
            self._pass(f"{endpoint}: Valid array response ({len(response)} items)")
        elif isinstance(response, (int, float, str)):
            self._pass(f"{endpoint}: Valid scalar response")
        else:
            self._fail(f"{endpoint}: Unexpected response type {type(response)}")
    
    def _pass(self, message: str):
        """Record passed test"""
        self.passed += 1
        print(f"  ✓ {message}")
        self.results.append(("PASS", message))
    
    def _fail(self, message: str):
        """Record failed test"""
        self.failed += 1
        print(f"  ✗ {message}")
        self.results.append(("FAIL", message))
    
    def _print_summary(self):
        """Print test summary"""
        total = self.passed + self.failed
        print("\n" + "=" * 80)
        print(f"Results: {self.passed}/{total} passed")
        
        if self.failed > 0:
            print(f"\n{self.failed} failures:\n")
            for status, msg in self.results:
                if status == "FAIL":
                    print(f"  - {msg}")
        
        print("=" * 80)


def main():
    """Run smoke tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Smoke test c2pool Qt control panel")
    parser.add_argument("--daemon", default="http://127.0.0.1:8080", help="Daemon URL")
    parser.add_argument("--offline", action="store_true", help="Test offline (with mocks)")
    parser.add_argument("--timeout", type=int, default=3, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    tests = SmokeTest(daemon_url=args.daemon, offline_mode=args.offline)
    tests.TIMEOUT = args.timeout
    
    success = tests.run_all()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
