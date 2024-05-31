import numpy as np

mat = np.zeros((500, 500), dtype=int)

data = open('message.txt', 'r').read().splitlines()
for i in range(len(data)):
    line = data[i]
    vals = []
    val = []
    for j in range(len(line)-2, -2, -2):
        if line[j:j+2] == 'ff':
            vals.append(''.join(val[::-1]))
            val = []
        else:
            val.append(line[j:j+2])
    vals = vals[::-1]
    column_position = 0
    for j in range(0, len(vals), 2):
        byte_count = int(vals[j], 16)
        byte_val = int(vals[j+1], 16)
        for k in range(column_position, column_position + byte_count):
            mat[k][i] = byte_val
        column_position += byte_count

f = open('decompressed.txt','w')
for i in range(len(mat)):
    row = mat[i]
    for j in range(len(row)):
        f.write(str(mat[i][j]) + ' ')
    f.write('\n')
f.close()