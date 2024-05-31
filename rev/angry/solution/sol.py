from z3 import *

# Create a solver instance
solver = Solver()

input_length = 37  # 222 / (2 + 2 + 2) = 37

input = [BitVec(f'input_{i}', 8) for i in range(input_length)]

for char in input:
    solver.add(char >= 0x20, char <= 0x7e)

# Translate the conditions from the compare function

# flag starts with L3AK{ and ends with }
solver.add(input[input_length - 1] == 0x7d)
solver.add(input[0] == 0x4c)
solver.add(input[1] == 0x33)
solver.add(input[2] == 0x41)
solver.add(input[3] == 0x4b)
solver.add(input[4] == 0x7b)


solver.add(input[5] * input[15] - input[7] == 4844)
solver.add(input[6] == 0x6e)
solver.add(-input[7] * -input[7] == 10609)
solver.add(input[8] ^ 0xde == 172)
solver.add(input[9] ^ 0xad == 242)
solver.add(input[10] << 2 == 208)
solver.add(input[11] == 0x5f)
solver.add(input[12] == 0x6c)
solver.add(input[13] ^ input[0] ^ input[1] ^ input[2] ^ input[3] == 68)
solver.add(input[14] + input[15] + input[16] + input[17] == 348)
solver.add(input[15] ^ input[1] ^ input[2] == 65)
solver.add(input[16] + input[21] - input[25] == 85)
solver.add(input[17] - input[32] + input[33] == 156)
solver.add(input[18] == 0x30)
solver.add(input[19] == 0x6e)
solver.add(input[20] == 0x74)
solver.add((input[21] ^ input[17]) == 59)
solver.add(input[22] == 0x64)
solver.add(input[23] ^ 3 + input[21] == 13)
solver.add(input[24] == 0x5f)
solver.add(input[25] - input[5] == 8)
solver.add(2 * input[26] - 2^10 == 172)
solver.add(input[27] == 0x5f)
solver.add(input[28] + input[21] - input[25] == 99)
solver.add(input[29] ^ input[31] + input[28] == 246)
solver.add(input[30] == 0x6e)
solver.add(input[31] ^ input[13] == 100)
solver.add(input[32] + input[33] == 160)
solver.add(input[33] - input[1] == 57)
solver.add(input[34] == 0x6c)
solver.add(input[35] == 0x79)
solver.add((input[34] + input[31] == 193))

solver.add(input[8] == 0x72)
solver.add(input[9] == 0x5f)
solver.add(input[23] == 444 >> 2)
solver.add(input[29] == 0x34)

solver.add((input[10] & ~0x30) < 10)

def find_all_solutions(solver, input):
    solutions = []
    while solver.check() == sat:
        model = solver.model()
        result = ''.join([chr(model[char].as_long()) for char in input])
        solutions.append(result)
        
        # Create a constraint to block the current solution
        block = []
        for char in input:
            block.append(char != model[char])
        solver.add(Or(block))
    
    return solutions

# Example usage:
# Assuming `solver` and `input` are already defined and configured
solutions = find_all_solutions(solver, input)
if solutions:
    for solution in solutions:
        print(f"Solved input: {solution}")
else:
    print("No solution found.")
