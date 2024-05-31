from sage.all import QQ
from sage.all import ZZ
from sage.all import matrix
from sage.all import vector
from Crypto.Util.number import long_to_bytes as ltb

# From: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py
def attack(y, k, s, m, a, c):
    """
    Recovers the states associated with the outputs from a truncated linear congruential generator.
    More information: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"
    :param y: the sequential output values obtained from the truncated LCG (the states truncated to s most significant bits)
    :param k: the bit length of the states
    :param s: the bit length of the outputs
    :param m: the modulus of the LCG
    :param a: the multiplier of the LCG
    :param c: the increment of the LCG
    :return: a list containing the states associated with the provided outputs
    """
    diff_bit_length = k - s

    # Preparing for the lattice reduction.
    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        # Shift output value to the MSBs and remove the increment.
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    # This lattice only works for increment = 0.
    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1

    B = B.LLL()

    # Finding the target value to solve the equation for the states.
    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    # Recovering the states
    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        # Adding the MSBs and the increment back again.
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x

# From prng.vhdl
A = 73067557
C = 111837721
M = 0x10000000
#s = 0x0e6e9eeb # Players don't know this
enc = ltb(0x50E9A87F3B317119319E286313520AFDE00A710D156B75482373F4332473A876E2BAD778B67FD5B4)

# Use our knowledge of the flag wrapper to get the first 5 consecutive outputs of the truncated LCG
key = []
wrapper = b'L3AK{'
for i in range(5):
    key.append(enc[i] ^ wrapper[i])

# Recover the initial LCG states using lattice reduction
recovered_states = attack(key, 28, 8, M, A, C)
state = recovered_states[0]
for s in recovered_states[1:]:
    next_state = (state * A + C) % M
    assert(next_state == s)
    state = next_state

# Use the recovered LCG state to get the rest of the XOR key and find the flag!
for i in range(35):
    state = (state * A + C) % M
    state_truncated = int(bin(state)[2:].zfill(28)[:8], 2)
    key.append(state_truncated)

flag = b''.join([ltb(x^y) for x,y in zip(key, enc)]).decode()
print(flag)

# L3AK{Y0u_C4N_d0_M4NY_Th1ngS_w1Th_VHDL!!} 
