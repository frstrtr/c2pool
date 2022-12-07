def target_to_average_attempts(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2 ** 256: print('target >= 2**256!')
    return 2 ** 256 // (target + 1)


def average_attempts_to_target(average_attempts):
    assert average_attempts > 0
    return min(int(2 ** 256 / average_attempts - 1 + 0.5), 2 ** 256 - 1)


def target_to_difficulty(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2 ** 256: print('target >= 2**256!')
    return (0xffff0000 * 2 ** (256 - 64) + 1) / (target + 1)


def difficulty_to_target(difficulty):
    assert difficulty >= 0
    if difficulty == 0: return 2 ** 256 - 1
    print('div diff: {0}'.format((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty))
    print('circ: {0}'.format((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5))
    print('circ_without: {0}'.format((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1))
    print('cast: {0}'.format(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5)))
    print('cast_without: {0}'.format(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1)))
    return min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)


def t2d_test(num):
    print('\ntarget to difficulty for {0}:'.format(hex(num)))
    res = target_to_difficulty(num)
    print("result = {0}".format(res))
    print('hex = {0}'.format(hex(res)))
    return res


def d2t_test(num):
    print('\ndifficulty to target for {0}:'.format(hex(num)))
    res = difficulty_to_target(num)
    print("result = {0}".format(res))
    print('hex = {0}'.format(hex(res)))


# target to difficulty
diff1 = t2d_test(2 ** (256 / 2))
diff2 = t2d_test(2 ** 256 - 1)
diff3 = t2d_test(1)
diff4 = t2d_test(30)

print('\n###########\ndifficulty to target\n###########')
# difficulty to target
d2t_test(diff1)
d2t_test(diff2)
d2t_test(diff3)
d2t_test(diff4)
