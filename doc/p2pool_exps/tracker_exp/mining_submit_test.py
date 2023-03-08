import pack
import coind_data
import coind_getwork as getwork
import net as _net

net = _net

def bytes_to_data(bytes):
    res = b''
    for x in bytes:
        res += chr(x)
    return res #str(res).replace(', ', ' ')


########################################## CODE
target = int('00000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)
share_info = dict(
    bits = pack.FloatingInteger(504365055)
)


worker_name = "antminer_1"
job_id = "baf22d3aaadb7995e8ecd2194aceb7a0"
extranonce2 = "0100000000000000"
ntime = "6409ea67"
nonce = "da420580"

#(NotifyData: 
#  version = 536870914,
#  previous_block = 0000000000000002546728190d372dfcd0ead7b5122019b41400024b45bea8ba,
#  merkle_link = (MerkleLink: branch = [ ], index = 0),
#  coinb1 = [ 1 0 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 6 4 203 188 255 0 0 0 0 0 0 4 0 0 0 0 0 0 0 0 38 106 36 170 33 169 237 82 121 208 219 62 217 225 145 115 20 19 42 211 74 46 23 133 225 176 102 66 45 41 227 137 221 66 82 29 79 69 243 165 96 27 12 0 0 0 0 25 118 169 20 208 230 206 121 50 250 194 135 15 183 85 220 74 170 149 134 122 214 236 120 136 172 151 32 72 105 9 0 0 0 169 82 33 3 138 184 47 58 79 86 156 69 113 196 131 213 103 41 232 51 153 121 91 173 179 40 33 202 182 77 4 231 181 209 6 134 65 4 255 208 61 228 74 110 17 185 145 127 58 41 249 68 50 131 217 135 28 157 116 62 243 13 94 221 205 55 9 75 100 209 179 216 9 4 150 181 50 86 120 107 245 200 41 50 236 35 195 183 77 159 5 166 249 90 139 85 41 53 38 86 102 75 65 4 87 163 55 184 101 87 245 177 92 148 84 74 210 103 249 106 88 45 194 185 30 104 115 150 143 247 186 23 79 218 104 116 175 151 156 217 175 65 236 32 50 223 223 214 88 123 229 177 74 67 85 84 109 84 19 136 195 241 85 90 103 209 28 45 83 174 0 0 0 0 0 0 0 0 42 106 40 224 103 14 243 190 77 23 81 199 46 95 202 255 145 27 191 227 249 233 211 127 141 86 164 62 184 168 189 238 47 176 143 0 0 0 0 0 0 0 0 1 32 91 67 50 80 111 111 108 93 91 67 50 80 111 111 108 93 91 67 50 80 111 111 108 93 ],
#  coinb2 = [ 0 0 0 0 ],
#  timestamp = 1678086619,
#  bits = 453024476,
#  share_target = 00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)

x = dict(
    version = 536870914,
    previous_block = int('00000000000000022638a1a387d366f5e7f8f18effd1ed754b31ee7cb9fb17a7', 16),
    coinb1 = bytes_to_data([1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 4, 37, 7, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 82, 121, 208, 219, 62, 217, 225, 145, 115, 20, 19, 42, 211, 74, 46, 23, 133, 225, 176, 102, 66, 45, 41, 227, 137, 221, 66, 82, 29, 79, 69, 243, 165, 96, 27, 12, 0, 0, 0, 0, 25, 118, 169, 20, 208, 230, 206, 121, 50, 250, 194, 135, 15, 183, 85, 220, 74, 170, 149, 134, 122, 214, 236, 120, 136, 172, 151, 32, 72, 105, 9, 0, 0, 0, 169, 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174, 0, 0, 0, 0, 0, 0, 0, 0, 42, 106, 40, 2, 136, 13, 114, 213, 57, 41, 195, 143, 3, 149, 249, 112, 65, 93, 208, 124, 228, 100, 50, 162, 183, 155, 236, 183, 246, 42, 155, 157, 239, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 1, 32, 91, 67, 50, 80, 111, 111, 108, 93, 91, 67, 50, 80, 111, 111, 108, 93, 91, 67, 50, 80, 111, 111, 108, 93]),
    coinb2 = bytes_to_data([0, 0, 0, 0]),
    merkle_link = dict(
        branch=[],
        index=0
    ),
    bits = pack.FloatingInteger(453035321)
)

# stratum mining.submit
coinb_nonce = extranonce2.decode('hex')
coinb_nonce_copy = extranonce2.decode('hex')
print("coinb_nonce = {0}".format([_x for _x in coinb_nonce_copy]))
assert len(coinb_nonce) == 8

new_packed_gentx = x['coinb1'] + coinb_nonce + x['coinb2']
print("new_packed_gentx = {0}".format([_x for _x in new_packed_gentx]))

header = dict(
    version=x['version'],
    previous_block=x['previous_block'],
    merkle_root=coind_data.check_merkle_link(coind_data.hash256(new_packed_gentx), x['merkle_link']), # new_packed_gentx has witness data stripped
    timestamp=pack.IntType(32).unpack(getwork._swap4(ntime.decode('hex'))),
    bits=x['bits'],
    nonce=pack.IntType(32).unpack(getwork._swap4(nonce.decode('hex'))),
)
print('HEADER = {0}'.format(header))
#got_response

pow_hash = net.PARENT.POW_FUNC(coind_data.block_header_type.pack(header))
print('pow_hash = {0}'.format(pow_hash))
print('pow_hash <= header[\'bits\'].target: {0}'.format(pow_hash <= header['bits'].target))
print('pow_hash <= share_info[\'bits\'].target: {0}'.format(pow_hash <= share_info['bits'].target))
print('pow_hash > target: {0}'.format(pow_hash > target))

######################################################################
