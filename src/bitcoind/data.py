import warnings

#--------------------additional---------------------------

def hex_to_int(hex_str):
    return int(hex_str, 16)

#--------------------bitcoind-data------------------------

def target_to_average_attempts(hex_target):
    target = hex_to_int(hex_target)
    assert 0 <= target and isinstance(target, int), target
    if target >= 2**256: warnings.warn('target >= 2**256!')
    return 2**256//(target + 1)

def average_attempts_to_target(hex_average_attempts):
    average_attempts = hex_to_int(hex_average_attempts)
    assert average_attempts > 0
    return min(int(2**256/average_attempts - 1 + 0.5), 2**256-1)

def target_to_difficulty(hex_target):
    target = hex_to_int(hex_target)
    assert 0 <= target and isinstance(target, int), target
    if target >= 2**256: warnings.warn('target >= 2**256!')
    return (0xffff0000 * 2**(256-64) + 1)/(target + 1)

def difficulty_to_target(hex_difficulty):
    difficulty = hex_to_int(hex_difficulty)
    assert difficulty >= 0
    if difficulty == 0: return 2**256-1
    return min(int((0xffff0000 * 2**(256-64) + 1)/difficulty - 1 + 0.5), 2**256-1)


def debug():
    print('target_to_average_attempts:')
    print(target_to_average_attempts('0'))
    print(target_to_average_attempts('1'))
    print(target_to_average_attempts('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))

    print('average_attempts_to_target:')
    print(average_attempts_to_target('1'))
    print(average_attempts_to_target('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))

    print('target_to_difficulty:')
    print(target_to_difficulty('0'))
    print(target_to_difficulty('1'))
    print(target_to_difficulty('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))

    print('difficulty_to_target:')
    print(difficulty_to_target('1'))
    print(difficulty_to_target('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))

#debug()