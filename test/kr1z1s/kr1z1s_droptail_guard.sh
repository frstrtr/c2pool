#!/usr/bin/env bash
# CI guard for the L-KR1Z1S drop_tails release-order race (SIGSEGV drop_tails,
# fixed on master by the coupled pair main_ltc.cpp:5011 (caller unlocks the
# tracker mutex before notify) + node.cpp:1038 (deref under the lock).
#
# This is a SELF-CONTAINED STAND-IN: it compiles and runs a small harness that
# does NOT link NodeImpl / main_ltc. A literal git-revert of main_ltc.cpp:5011
# therefore does NOT flip this test; MODE=deadcode instead MODELS that mutation
# (caller holds the tracker mutex EXCLUSIVE across notify, so the IO try_to_lock
# defers forever and the invariant never runs -> io_ops==0 -> RED). MODE=uaf
# models the node.cpp:1038 mutation (cache a node ptr under the lock, deref it
# after release) and reds deterministically under AddressSanitizer.
#
# Three modes, one ASan binary:
#   green    -> exit 0, "PASS(GREEN)"                 (fixed discipline holds)
#   deadcode -> exit != 0, "FAIL(RED): io_ops==0"     (models main_ltc.cpp:5011)
#   uaf      -> ASan "heap-use-after-free", exit != 0  (models node.cpp:1038)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/kr1z1s_droptail_harness.cpp"
CXX="${CXX:-g++}"
BIN="$(mktemp -d)/kr1z1s_guard"

echo "[guard] compiling $SRC with AddressSanitizer ($CXX)"
"$CXX" -std=c++17 -O1 -g -fsanitize=address -pthread "$SRC" -o "$BIN" || { echo "[guard] FAIL: compile"; exit 2; }
echo "[guard] binary sha256=$(sha256sum "$BIN" | cut -d" " -f1)"

fail=0
export ASAN_OPTIONS="abort_on_error=0:exitcode=1:detect_leaks=0"

# --- GREEN: fixed discipline survives concurrent prune ---
out="$(MODE=green   CHAIN_SIZE=18300 ITERS=300 "$BIN" 2>&1)"; rc=$?
echo "$out"
if [ $rc -ne 0 ] || ! grep -q "PASS(GREEN)" <<<"$out"; then echo "[guard] FAIL: green expected exit0+PASS(GREEN), got rc=$rc"; fail=1; fi

# --- DEADCODE: models main_ltc.cpp:5011 revert -> io_ops==0 -> RED ---
out="$(MODE=deadcode CHAIN_SIZE=18300 ITERS=300 "$BIN" 2>&1)"; rc=$?
echo "$out"
if [ $rc -eq 0 ] || ! grep -q "FAIL(RED): io_ops==0" <<<"$out"; then echo "[guard] FAIL: deadcode expected nonzero+io_ops==0 RED, got rc=$rc"; fail=1; fi

# --- UAF: models node.cpp:1038 revert -> ASan heap-use-after-free ---
out="$(MODE=uaf      CHAIN_SIZE=18300 ITERS=300 "$BIN" 2>&1)"; rc=$?
echo "$out" | head -20
if [ $rc -eq 0 ] || ! grep -q "heap-use-after-free" <<<"$out"; then echo "[guard] FAIL: uaf expected ASan heap-use-after-free, got rc=$rc"; fail=1; fi

if [ $fail -ne 0 ]; then echo "[guard] RESULT: FAIL"; exit 1; fi
echo "[guard] RESULT: PASS (green survives; deadcode+uaf red deterministically)"
exit 0
