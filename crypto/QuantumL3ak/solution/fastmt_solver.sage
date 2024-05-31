import tqdm
import time

from fastmt import MT19937
import numpy

load("fill_matrix.spyx")

class MT19937Solver:
    def __init__(self):
        self.model = MT19937()
        self.observed = []

    def submit(self, bits, value):
        bit_expressions = self.model.getrandbits(bits).mat[:bits,:]

        # cannot extend observed
        # this call will have simply advanced the state
        if value is None:
            return

        for i, expr in zip(range(bits), bit_expressions):
            if value[i] is not None:
                expr = numpy.unpackbits(expr.view(numpy.uint8), bitorder='little')
                self.observed.append((expr, value[i]))
        
    def v2n(self, vec):
        acc = 0
        for i, v in enumerate(vec):
            acc += 2**i * int(v)
        return acc

    def solve(self):
        size = self.model.N * self.model.W
        rows = []
        observed_values = []
        observed = vector(GF(2), len(self.observed))
        print("Constructing rows and observed values")
        shape = (int(len(observed)),int(624*32))
        rows = numpy.zeros(shape=shape, dtype=numpy.uint32)
        for i,(row, value) in tqdm.tqdm(enumerate(self.observed)):
            observed[i] = value
            rows[i] = row
        # Create Matrix
        start = time.time()
        M = Matrix(GF(2), len(self.observed), size)
        print("Filling Matrix...")
        #for i,(row, value) in tqdm.tqdm(enumerate(self.observed)):
        #    #for j in range(len(row)):
        #    #    M[i,j] = row[j]
        #    M.set_row(i,row)
        #    #fill_matrix_row(M, i, len(row), row)
        #    eqns.append(row)
        #    #observed[i] = value
        fill_matrix(M, rows)
        print("Filled Matrix:", time.time() - start)
        print("Solving Matrix for observed vector")
        self.M = M
        start = time.time()
        solution = M \ observed
        print("Computed solution:", time.time() - start)
        print("Converting to numbers...")
        res = []
        for i in range(624):
            res.append(self.v2n(solution[32*i:32*(i+1)]))
        return res

def test2():
    import random
    mrand = MT19937Solver()
    rand = random.Random(int(1))
    initial_state = rand.__getstate__()[1][:-1]
    #b = rand.choices([0,1,2,3], weights=[1,1,1,1])[0]
    b = rand.getrandbits(32)
    mrand.submit(32,[None]*31 + [b>>31])
    for i in tqdm.tqdm(range(624*16)):
        #b = (rand.getrandbits(32) >> 30) & 3
        #b1 = b >> 1
        #b2 = b & 1
        #_ = (rand.getrandbits(32) >> 30) & 3
        b = rand.choices([0,1,2,3], weights=[1,1,1,1])[0]
        #mrand.submit(32, [None]*30+[b2, b1])
        mrand.submit(32, [None]*30 + [b&1,b>>1])
        mrand.submit(32, None)
    result = mrand.solve()
    for i in range(len(initial_state)):
        print(initial_state[i], result[i])

if __name__ == "__main__":
    test2()
