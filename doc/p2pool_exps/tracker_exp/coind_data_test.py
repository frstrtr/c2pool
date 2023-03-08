import coind_data

print(coind_data.calculate_merkle_link([None], 0))

# print(coind_data.calculate_merkle_link([0, int('f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d', 16)], 0))
# print(coind_data.calculate_merkle_link([None, int('f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d', 16), int('d85c2a7eefa6bf21ad0457ccbbcf3507f78fd1d5919c637c6679a83b1b75675f', 16)], 1))

print(hex(coind_data.difficulty_to_target(1)))
print(hex(coind_data.difficulty_to_target(float(1.0 / 2**16))))