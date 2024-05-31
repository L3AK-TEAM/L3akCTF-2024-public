import numpy
import time
import tqdm
#import numba
#from numba import uint64
#from numba.experimental import jitclass

matrices = {}
def matrix(n):
    if n in matrices:
        return matrices[n]
    M = numpy.array([[(n>>i) & 1 for i in range(32)]], dtype=numpy.uint32)
    matrices[n] = M
    return M

xormatices = {}
def xormatrix(n):
    xor = []
    for i in range(32):
        if (n >> i) & 1:
            xormatrix.append([1]*624)
        else:
            xormatrix.append([0]*624)
    xormatrix = numpy.array(xormatrix)
    xormatrices[n] = xormatrix
    return xormatrix

def show_non_zero(array):
    for i, e in enumerate(array):
        if e != 0:
            print((i,e))

#spec = [('mat', uint64)]

class FastSymMersenne:
    def __init__(self, shape=None, matrix=None):
        if matrix is not None:
            self.mat = matrix
            return
        raise Exception("Specify either shape or matrix")

    def __xor__(self, other):
        if isinstance(other, int):
            other = xormatrix(other)
        else:
            other = other.mat
        return FastSymMersenne(matrix=self.mat ^ other)

    __rxor__ = __xor__

    def __mul__(self, other):
        assert isinstance(other, int) and other >= 0
        assert (self.mat[1:] == 0).all()
        C = self.mat.copy()
        M = matrix(other)
        for i in range(32):
            C[i,:] = C[0,:] * M[0,i]
        return FastSymMersenne(matrix=C)

    def __rmul__(self, other):
      return self * other

    def __rshift__(self, other : int):
        assert isinstance(other, int)
        assert self.mat.shape[0] >= other
        C = self.mat.copy()
        k = other
        C[:k,:] = 0
        C = numpy.roll(C, -k, axis=0)
        return FastSymMersenne(matrix=C)

    def __lshift__(self, other : int):
        assert isinstance(other, int)
        assert self.mat.shape[0] >= other
        C = self.mat.copy()
        k = other
        C[-k:,:] = 0
        C = numpy.roll(C, k, axis=0)
        return FastSymMersenne(matrix=C)

    def __and__(self, other):
        assert isinstance(other, int)
        # This is just multiplication
        M = matrix(other)
        return FastSymMersenne(matrix=M.transpose()*self.mat)

    #def __repr__(self):
    #    return repr(self.mat)

class MT19937:
    W = 32
    N = 624
    M = 397
    R = 31
    A = 0x9908B0DF
    U = 11
    D = 0xFFFFFFFF
    S = 7
    B = 0x9D2C5680
    T = 15
    C = 0xEFC60000
    L = 18

    F = 1812433253

    def __init__(self):
        self.state = []
        for i in range(624):
            mat = numpy.zeros(shape=(32,624),dtype=numpy.uint32) # 32 rows for each bit, 624 contributors
            for j in range(32):
                mat[j,i] = 2**j # the initial jth bit 
            self.state.append(FastSymMersenne(matrix=mat))
        self.idx = self.N

    def rand(self):
        if self.idx >= self.N:
            self._twist()
        y = self.state[self.idx]
        assert not ((y.mat == 0).all())
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= y >> self.L
        self.idx += 1
        return y

    def getrandbits(self, n):
        assert n <= 32
        n = int(n)
        return self.rand() >> (32 - n)

    def _twist(self):
        lower_mask = (1 << self.R) - 1
        upper_mask = 2**self.W - 1 - lower_mask
        for i in range(0, self.N):
            x = (self.state[i] & upper_mask) ^ (self.state[(i + 1) % self.N] & lower_mask)
            xA = x >> 1
            xA ^= (x & 1) * self.A
            self.state[i] = self.state[(i + self.M) % self.N] ^ xA
        self.idx = 0

class MT19937Solver:
    def __init__(self):
        self.model = MT19937()
        self.observed = []

    def submit(self, bits, value):
        bit_expressions = self.model.getrandbits(bits).mat[:bits]

        # cannot extend observed
        # this call will have simply advanced the state
        if value is None:
            return bit_expressions

        for i, expr in zip(range(bits), bit_expressions):
            if value[i] is not None:
                expr = numpy.unpackbits(expr.view(numpy.uint8), bitorder='little')
                self.observed.append((expr, value[i]))
        return bit_expressions
        
    def v2n(self, vec):
        acc = 0
        for i, v in enumerate(vec):
            acc += 2**i * int(v)
        return acc

    def solve(self):
        size = self.model.N * self.model.W
        flatten = []
        observed = []
        for expr, value in self.observed:
            flatten.append(expr)
            observed.append(value)
        M = numpy.array(flatten)
        print("\nShape:",M.shape,"\n")
        observed = numpy.array(observed)
        observed = observed.reshape((len(observed), 1))
        print("\nShape:",observed.shape,"\n")
        solution = gaussian_eliminate(M, observed)
        res = []
        for i in range(624):
            res.append(self.v2n(solution[32*i:32*(i+1)]))
        return res


def test():
    MT = MT19937()
    print("inited!")
    for i in range(624*32*2):
        res = MT.rand()
    print("done")
    print(MT.state[0].mat[0,:])
def test2():
    import random
    mrand = MT19937Solver()
    rand = random.Random(int(1))
    initial_state = rand.__getstate__()[1][:-1]
    for i in tqdm.tqdm(range(624*32)):
        b = (rand.getrandbits(32) >> 31) & 1
        _ = (rand.getrandbits(32) >> 31) & 1
        mrand.submit(32, [None]*31+[b])
        mrand.submit(32, None)
    result = mrand.solve()
    for i in range(len(initial_state)):
        print(initial_state[i], result[i])

if __name__ == "__main__":
    test2()
