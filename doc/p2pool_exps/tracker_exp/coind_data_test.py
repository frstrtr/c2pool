import coind_data
import pack

print(coind_data.calculate_merkle_link([None], 0))

# print(coind_data.calculate_merkle_link([0, int('f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d', 16)], 0))
# print(coind_data.calculate_merkle_link([None, int('f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d', 16), int('d85c2a7eefa6bf21ad0457ccbbcf3507f78fd1d5919c637c6679a83b1b75675f', 16)], 1))

print(coind_data.target_to_difficulty(int("00000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)))
print(hex(coind_data.difficulty_to_target(1)))
print('1/DUMB = {0}'.format(hex(coind_data.difficulty_to_target(float(1.0 / 2**16)))))

print(hex(coind_data.hash256('1234')))


#===========================

merkle_hash = coind_data.merkle_hash([
            0xb53802b2333e828d6532059f46ecf6b313a42d79f97925e457fbbfda45367e5c,
            0x326dfe222def9cf571af37a511ccda282d83bedcc01dabf8aa2340d342398cf0,
            0x5d2e0541c0f735bac85fa84bfd3367100a3907b939a0c13e558d28c6ffd1aea4,
            0x8443faf58aa0079760750afe7f08b759091118046fe42794d3aca2aa0ff69da2,
            0x4d8d1c65ede6c8eab843212e05c7b380acb82914eef7c7376a214a109dc91b9d,
            0x1d750bc0fa276f89db7e6ed16eb1cf26986795121f67c03712210143b0cb0125,
            0x5179349931d714d3102dfc004400f52ef1fed3b116280187ca85d1d638a80176,
            0xa8b3f6d2d566a9239c9ad9ae2ed5178dee4a11560a8dd1d9b608fd6bf8c1e75,
            0xab4d07cd97f9c0c4129cff332873a44efdcd33bdbfc7574fe094df1d379e772f,
            0xf54a7514b1de8b5d9c2a114d95fba1e694b6e3e4a771fda3f0333515477d685b,
            0x894e972d8a2fc6c486da33469b14137a7f89004ae07b95e63923a3032df32089,
            0x86cdde1704f53fce33ab2d4f5bc40c029782011866d0e07316d695c41e32b1a0,
            0xf7cf4eae5e497be8215778204a86f1db790d9c27fe6a5b9f745df5f3862f8a85,
            0x2e72f7ddf157d64f538ec72562a820e90150e8c54afc4d55e0d6e3dbd8ca50a,
            0x9f27471dfbc6ce3cbfcf1c8b25d44b8d1b9d89ea5255e9d6109e0f9fd662f75c,
            0x995f4c9f78c5b75a0c19f0a32387e9fa75adaa3d62fba041790e06e02ae9d86d,
            0xb11ec2ad2049aa32b4760d458ee9effddf7100d73c4752ea497e54e2c58ba727,
            0xa439f288fbc5a3b08e5ffd2c4e2d87c19ac2d5e4dfc19fabfa33c7416819e1ec,
            0x3aa33f886f1357b4bbe81784ec1cf05873b7c5930ab912ee684cc6e4f06e4c34,
            0xcab9a1213037922d94b6dcd9c567aa132f16360e213c202ee59f16dde3642ac7,
            0xa2d7a3d2715eb6b094946c6e3e46a88acfb37068546cabe40dbf6cd01a625640,
            0x3d02764f24816aaa441a8d472f58e0f8314a70d5b44f8a6f88cc8c7af373b24e,
            0xcc5adf077c969ebd78acebc3eb4416474aff61a828368113d27f72ad823214d0,
            0xf2d8049d1971f02575eb37d3a732d46927b6be59a18f1bd0c7f8ed123e8a58a,
            0x94ffe8d46a1accd797351894f1774995ed7df3982c9a5222765f44d9c3151dbb,
            0x82268fa74a878636261815d4b8b1b01298a8bffc87336c0d6f13ef6f0373f1f0,
            0x73f441f8763dd1869fe5c2e9d298b88dc62dc8c75af709fccb3622a4c69e2d55,
            0xeb78fc63d4ebcdd27ed618fd5025dc61de6575f39b2d98e3be3eb482b210c0a0,
            0x13375a426de15631af9afdf00c490e87cc5aab823c327b9856004d0b198d72db,
            0x67d76a64fa9b6c5d39fde87356282ef507b3dec1eead4b54e739c74e02e81db4,
        ])

print('Merkle_hash = {0}'.format(hex(merkle_hash)))

#====================================

merkle_hash2 = coind_data.merkle_hash([
            0xb53802b2333e828d6532059f46ecf6b313a42d79f97925e457fbbfda45367e5c,
            0x326dfe222def9cf571af37a511ccda282d83bedcc01dabf8aa2340d342398cf0,
            0x5d2e0541c0f735bac85fa84bfd3367100a3907b939a0c13e558d28c6ffd1aea4
        ])

print('Merkle_hash2 = {0}'.format(hex(merkle_hash2)))


###############

print(pack.FloatingInteger(504365055).target)
print(int('00000fffff000000000000000000000000000000000000000000000000000000', 16))

print(pack.FloatingInteger(504365055).target == int('00000fffff000000000000000000000000000000000000000000000000000000', 16))

###############


local_hash_rate = int('000000000000000000000000000000000000000000000000000000000000000000369d03', 16)
_SHARE_PERIOD = 25
print(local_hash_rate * _SHARE_PERIOD / 0.0167)
print(coind_data.average_attempts_to_target(local_hash_rate * _SHARE_PERIOD / 0.0167))
_target = 53919893334301279589334030174039261347274288845081144962207220498431
print u'diff = %s' % (coind_data.difficulty_to_target(_target))
# print(coind_data.target_to_difficulty(53919893334301279589334030174039261347274288845081144962207220498431)*65565)
print u'%s' % (coind_data.difficulty_to_target(0.499992370605))

print("\n\n\n\n\n")

tip_hash = int('9ac4b53e4eb96fe39364cd0ebd8ce3af1b918c99de4be4d05a6db50a057b12ae', 16)
print(hex(coind_data.check_merkle_link(tip_hash, coind_data.calculate_merkle_link([None], 0))))

#########
print(hex(pack.FloatingInteger(503351432).target))
print(hex(pack.FloatingInteger(504365055).target))
