import data
import net as _net
import coind_data
import pack
import share
import p2pool_math

def hex_to_bytes(_hex):
    return ''.join(chr(int(_hex[i:i+2], 16)) for i in range(0, len(_hex), 2))

def bytes_to_data(bytes):
    res = b''
    for x in bytes:
        res += chr(x)
    return res #str(res).replace(', ', ' ')


net = _net

DONATION_SCRIPT = '5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae'.decode('hex')
gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

#contents=========
segwit_activated = True

# _merkle_root = dict(
      
# )
# _header = dict(_min_header, merkle_root=_merkle_root)
##############

known_txs = {
    int('bb8dd34961460ce315a67e6365a18517f363d23504fb9fd493f6d6c78b76c02f', 16):
    dict(
        version = 2,
        tx_ins = [
            dict(
                previous_output = dict(
                    hash = int('d6f2c8a37a4a917131237122fcbe9ba21e7c399cb05e5d16832cc4439c4e4305', 16),
                    index = 2
                ),
                script = bytes_to_data([72, 48, 69, 2, 33, 0, 208, 177, 34, 169, 30, 206, 234, 142, 228, 189, 69, 250, 181, 19, 235, 39, 32, 135, 242, 13, 249, 153, 105, 126, 117, 23, 79, 10, 112, 204, 157, 220, 2, 32, 61, 203, 126, 189, 88, 73, 201, 229, 17, 122, 202, 235, 11, 123, 32, 60, 226, 123, 212, 153, 126, 77, 78, 12, 84, 80, 170, 239, 76, 248, 125, 143, 1, 33, 3, 18, 127, 139, 165, 182, 217, 37, 48, 41, 176, 72, 231, 121, 214, 115, 60, 147, 88, 242, 216, 236, 142, 98, 178, 106, 76, 8, 70, 239, 25, 168, 35]),#bytes_to_data([71, 48, 68, 2, 32, 18, 186, 133, 223, 96, 104, 192, 61, 212, 89, 217, 34, 174, 141, 75, 226, 0, 63, 230, 9, 158, 33, 164, 163, 192, 244, 206, 43, 194, 159, 187, 51, 2, 32, 87, 67, 222, 224, 151, 174, 21, 123, 236, 29, 21, 82, 177, 198, 61, 43, 116, 232, 17, 111, 48, 188, 138, 187, 199, 74, 55, 214, 167, 8, 134, 236, 1, 33, 3, 225, 125, 76, 174, 80, 133, 76, 137, 76, 26, 140, 206, 184, 141, 8, 6, 29, 35, 176, 115, 48, 104, 95, 39, 248, 192, 233, 41, 116, 21, 21, 51]),
                sequence = None
            )
        ],
        tx_outs = [
            dict(
                value = 1000000,
                script = bytes_to_data([118, 169, 20, 66, 50, 183, 234, 46, 3, 36, 151, 20, 48, 134, 194, 220, 214, 115, 70, 43, 221, 46, 115, 136, 172])
            ),
            dict(
                value = 0,
                script = bytes_to_data([106, 29, 119, 105, 116, 104, 100, 114, 97, 119, 110, 32, 102, 114, 111, 109, 32, 100, 105, 103, 105, 102, 97, 117, 99, 101, 116, 46, 111, 114, 103])
            ),
            dict(
                value = 1068872282543,
                script = bytes_to_data([118, 169, 20, 94, 27, 66, 154, 31, 153, 42, 240, 33, 18, 8, 143, 172, 6, 157, 230, 253, 53, 181, 102, 136, 172])
            ),
            # dict(
            #     value = 1069696532921,
            #     script = bytes_to_data([118, 169, 20, 94, 27, 66, 154, 31, 153, 42, 240, 33, 18, 8, 143, 172, 6, 157, 230, 253, 53, 181, 102, 136, 172])
            # )
        ],
        lock_time = 0,
        # marker = 0,
        # flag = 1,
        # witness = [[bytes_to_data([48, 68, 2, 32, 48, 67, 6, 98, 155, 39, 67, 72, 244, 68, 204, 126, 16, 168, 20, 23, 159, 8, 172, 252, 135, 144, 253, 180, 193, 146, 77, 62, 124, 80, 115, 12, 2, 32, 17, 40, 231, 119, 53, 96, 188, 54, 183, 84, 184, 165, 17, 113, 200, 27, 80, 231, 57, 173, 28, 57, 69, 209, 88, 22, 42, 138, 115, 62, 176, 171, 1]),
        #             bytes_to_data([3, 74, 109, 112, 14, 31, 207, 206, 180, 117, 64, 178, 93, 115, 157, 217, 28, 132, 209, 3, 49, 145, 84, 188, 224, 109, 45, 235, 90, 97, 241, 42, 65])]]
    )
}

other_transaction_hashes = [int('bb8dd34961460ce315a67e6365a18517f363d23504fb9fd493f6d6c78b76c02f', 16)]
share_txs = [(known_txs[h], coind_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
segwit_data = dict(txid_merkle_link=coind_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=coind_data.merkle_hash([0] + [coind_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))

print('known_txs = {0}'.format(known_txs))
print('other_transaction_hashes = {0}'.format(other_transaction_hashes))
print('share_txs = {0}'.format(share_txs))
print('segwit_data = {0}'.format(segwit_data))

# _segwit_data1 = dict()
# _segwit_data2 = dict()


# __gentx_hash = int("e63b9f78cbc9a9d6749bd79b961699afae50f23a4054f5b0202a1d4dff0370f7", 16)
# __merkle_link = dict(branch = [int("66102b718408d8da8fed1bf04438f881a67c35e12aba341a30ae7e8d5bd64f15", 16), int("06da12f71256344a9fe06c07119727a81bfbeb9e0f04f7fd1fb315f935983e73", 16)], index=0)

# __merkle_root = coind_data.check_merkle_link(__gentx_hash, __merkle_link)
# print("__MERKLE_ROOT = {0}".format(hex(__merkle_root)))

