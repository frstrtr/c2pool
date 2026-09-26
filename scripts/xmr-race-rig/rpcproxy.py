#!/usr/bin/env python3
# Logging pass-through for monerod RPC: one line per request "ts path method". Witness for "0 submit_block".
import sys, json, time, urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
LISTEN, UP, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3]
logf = None
# Forward only the monerod RPC endpoints a node or wallet may use; any other path
# is refused (and still logged), so a request can never steer the upstream URL.
_ALLOWED = {p: p for p in (
    "/json_rpc", "/get_info", "/getinfo", "/getheight", "/get_height", "/get_transactions",
    "/gettransactions", "/get_transaction_pool", "/get_transaction_pool_hashes",
    "/get_transaction_pool_hashes.bin", "/get_transaction_pool_stats", "/sendrawtransaction",
    "/send_raw_transaction", "/getblocks.bin", "/get_blocks.bin", "/getblocks_by_height.bin",
    "/get_blocks_by_height.bin", "/gethashes.bin", "/get_hashes.bin", "/get_o_indexes.bin",
    "/get_outs.bin", "/get_outs", "/is_key_image_spent", "/get_alt_blocks_hashes",
    "/get_limit", "/get_fee_estimate", "/get_net_stats", "/get_public_nodes",
    "/get_output_distribution.bin")}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _do(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        m = "-"
        try:
            if body:
                j = json.loads(body)
                m = j.get("method", "-") if isinstance(j, dict) else "batch"
        except Exception:
            m = "?"
        logf.write("%.3f %s %s %s\n" % (time.time(), method, self.path, m))
        target = _ALLOWED.get(self.path.split("?", 1)[0])
        if target is None:
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
            return
        req = urllib.request.Request(UP + target, data=body, method=method)
        for k in ("Content-Type",):
            if self.headers.get(k): req.add_header(k, self.headers.get(k))
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(); code = r.status; ct = r.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as e:
            data = e.read(); code = e.code; ct = "application/json"
        except Exception as e:
            data = b""; code = 502; ct = "text/plain"
        self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self): self._do("POST")
    def do_GET(self): self._do("GET")
with open(LOG, "a", buffering=1) as logf:
    ThreadingHTTPServer(("127.0.0.1", LISTEN), H).serve_forever()
