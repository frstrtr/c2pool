# Oracle golden generator for BCH G2 coinbase-author KAT.
# Transcribes VERBATIM the v36 output-assembly from p2pool-merged-v36
# p2pool/data.py:920-1085 (generate_transaction, v36_active branch):
#   amounts = subsidy*weight//total_weight ;
#   total_donation = subsidy - sum(amounts) ;
#   if total_donation < 1 and subsidy>0: largest by (amount,script) -=1 ; recompute
#   amounts[DON] += total_donation
#   dests = sorted(scripts \ {DON}, key=(amounts[s], s))[-4000:]
#   payouts = [{value:amounts[s], script:s} for s in dests if amounts[s]] + [DON last]
import struct

COMBINED_DONATION_SCRIPT = bytes.fromhex('a9148c6272621d89e8fa526dd86acff60c7136be8e8587')
def p2pkh(b): return bytes.fromhex('76a914') + bytes([b])*20 + bytes.fromhex('88ac')
A=p2pkh(0xaa); B=p2pkh(0xbb); C=p2pkh(0xcc); D=p2pkh(0xdd)

def assemble_v36(weights, donation_weight, subsidy):
    total_weight = sum(weights.values()) + donation_weight
    amounts = dict((s, subsidy*w//total_weight) for s,w in weights.items())
    total_donation = subsidy - sum(amounts.values())
    if total_donation < 1 and subsidy > 0:
        largest = max(amounts, key=lambda k:(amounts[k], k))
        amounts[largest] -= 1
        total_donation = subsidy - sum(amounts.values())
    amounts[COMBINED_DONATION_SCRIPT] = amounts.get(COMBINED_DONATION_SCRIPT,0) + total_donation
    excluded = {COMBINED_DONATION_SCRIPT}
    dests = sorted([s for s in amounts if s not in excluded], key=lambda s:(amounts[s], s))[-4000:]
    payouts = [(s, amounts[s]) for s in dests if amounts[s]]
    payouts.append((COMBINED_DONATION_SCRIPT, amounts[COMBINED_DONATION_SCRIPT]))
    return payouts

def assemble_with_finderfee(weights, finder, donation_weight, subsidy):
    # NEGATIVE control: pre-v36 math (199/200 haircut) + subsidy//200 finder fee.
    total_weight = sum(weights.values()) + donation_weight
    amounts = dict((s, subsidy*(199*w)//(200*total_weight)) for s,w in weights.items())
    amounts[finder] = amounts.get(finder,0) + subsidy//200
    total_donation = subsidy - sum(amounts.values())
    if total_donation < 1 and subsidy > 0:
        largest = max(amounts, key=lambda k:(amounts[k], k))
        amounts[largest] -= 1
        total_donation = subsidy - sum(amounts.values())
    amounts[COMBINED_DONATION_SCRIPT] = amounts.get(COMBINED_DONATION_SCRIPT,0) + total_donation
    dests = sorted([s for s in amounts if s != COMBINED_DONATION_SCRIPT], key=lambda s:(amounts[s], s))[-4000:]
    payouts = [(s, amounts[s]) for s in dests if amounts[s]]
    payouts.append((COMBINED_DONATION_SCRIPT, amounts[COMBINED_DONATION_SCRIPT]))
    return payouts

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+struct.pack('<H',n)
    if n <= 0xffffffff: return b'\xfe'+struct.pack('<I',n)
    return b'\xff'+struct.pack('<Q',n)

def serialize(payouts):
    out = b''
    for script, value in payouts:
        out += struct.pack('<Q', value) + varint(len(script)) + script
    return out

SUB = 1_000_000_000
cases = {
 'CASE1_ordering_tie': assemble_v36({A:10,B:20,C:20,D:50}, 0, SUB),
 'CASE2_donation_forced_last': assemble_v36({A:40,B:20}, 40, SUB),
 'CASE3_v36_no_finderfee': assemble_v36({A:60,B:40}, 0, SUB),
 'CASE3_NEG_with_finderfee': assemble_with_finderfee({A:60,B:40}, A, 0, SUB),
}
names = {A.hex():'A',B.hex():'B',C.hex():'C',D.hex():'D',COMBINED_DONATION_SCRIPT.hex():'DON'}
for name, p in cases.items():
    print('=== %s ===' % name)
    for s,v in p: print('   %-4s value=%d' % (names.get(s.hex(),'?'), v))
    print('   OUTSECTION_HEX=%s' % serialize(p).hex())
