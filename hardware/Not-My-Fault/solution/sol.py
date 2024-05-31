import ast
from pwn import *
from enum import Enum
from hashlib import sha256
from binascii import unhexlify as unhex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl

class G1(Enum):
    AND  = 1
    NAND = 2
    OR   = 3
    NOR  = 4
    XOR  = 5
    XNOR = 6

class G2(Enum):
    INV  = 7
    BUF  = 8

gate_fingerprints = {}
gate_fingerprints[(0,0,0,1)] = G1.AND
gate_fingerprints[(1,1,1,0)] = G1.NAND
gate_fingerprints[(0,1,1,1)] = G1.OR
gate_fingerprints[(1,0,0,0)] = G1.NOR
gate_fingerprints[(0,1,1,0)] = G1.XOR
gate_fingerprints[(1,0,0,1)] = G1.XNOR

sensitivities = {}
sensitivities[G1.AND] = 1
sensitivities[G1.NAND] = 1
sensitivities[G1.OR] = 0
sensitivities[G1.NOR] = 0
sensitivities[G1.XOR] = 0
sensitivities[G1.XNOR] = 1

inverting = {}
inverting[G1.AND] = False
inverting[G1.NAND] = True
inverting[G1.OR] = False
inverting[G1.NOR] = True
inverting[G1.XOR] = False
inverting[G1.XNOR] = False

class Net:
    def __init__(self, net_id, val=None, is_input=False, input_val=None, is_gate_output=True, gate_in=None, gate_out=None):
        self.net_id = net_id
        self.val = val
        self.stuck_at = False
        self.is_input = is_input
        self.input_val = input_val
        self.is_gate_output = is_gate_output
        self.gate_in = gate_in
        self.gate_out = gate_out

class Gate1:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.two_inputs = True
        self.type = None

class Gate2:
    def __init__(self, gate_id, in1, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.out = out
        self.two_inputs = False
        self.type = None

class Circuit:

    def __init__(self, circuit_list):

        self.gates = {}
        self.nets = {}
        self.gates_layer = {}
        self.inputs = [None] * 32
        self.gate_types_1 = [G1.AND, G1.NAND, G1.OR, G1.NOR, G1.XOR, G1.XNOR]
        self.gate_types_2 = [G2.INV, G2.BUF]
        self.gate_id = 1

        for num_gates in (16, 8, 4, 2, 1):
            self.gates_layer[num_gates] = {}

        num_gates_16, num_gates_8, num_gates_4, num_gates_2, num_gates_1 = 0, 0, 0, 0, 0
        for tup in circuit_list:
            if len(tup) == 3:
                if num_gates_16 < 16:

                    net_id_1 = tup[0]
                    net_id_2 = tup[1]
                    out_id   = tup[2]

                    if net_id_1 not in self.nets:
                        n1 = Net(net_id_1, None, True, None, False)
                        self.nets[net_id_1] = n1
                    else:
                        n1 = self.nets[net_id_1]
                    
                    if net_id_2 not in self.nets:
                        n2 = Net(net_id_2, None, True, None, False)
                        self.nets[net_id_2] = n2
                    else:
                        n2 = self.nets[net_id_2]

                    if out_id not in self.nets:
                        n3 = Net(out_id)
                        self.nets[out_id] = n3
                    else:
                        n3 = self.nets[out_id]

                    g = Gate1(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g
                    self.gates_layer[16][num_gates_16] = g
                    self.gate_id += 1
                    num_gates_16 += 1

                    n1.gate_in = g
                    n2.gate_in = g
                    n3.gate_out = g
                
                elif num_gates_8 < 8:

                    net_id_1 = tup[0]
                    net_id_2 = tup[1]
                    out_id   = tup[2]

                    if net_id_1 not in self.nets:
                        n1 = Net(net_id_1)
                        self.nets[net_id_1] = n1
                    else:
                        n1 = self.nets[net_id_1]
                    
                    if net_id_2 not in self.nets:
                        n2 = Net(net_id_2)
                        self.nets[net_id_2] = n2
                    else:
                        n2 = self.nets[net_id_2]

                    if out_id not in self.nets:
                        n3 = Net(out_id)
                        self.nets[out_id] = n3
                    else:
                        n3 = self.nets[out_id]

                    g = Gate1(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g
                    self.gates_layer[8][num_gates_8] = g
                    self.gate_id += 1
                    num_gates_8 += 1

                    n1.gate_in = g
                    n2.gate_in = g
                    n3.gate_out = g
                
                elif num_gates_4 < 4:

                    net_id_1 = tup[0]
                    net_id_2 = tup[1]
                    out_id   = tup[2]

                    if net_id_1 not in self.nets:
                        n1 = Net(net_id_1)
                        self.nets[net_id_1] = n1
                    else:
                        n1 = self.nets[net_id_1]
                    
                    if net_id_2 not in self.nets:
                        n2 = Net(net_id_2)
                        self.nets[net_id_2] = n2
                    else:
                        n2 = self.nets[net_id_2]

                    if out_id not in self.nets:
                        n3 = Net(out_id)
                        self.nets[out_id] = n3
                    else:
                        n3 = self.nets[out_id]

                    g = Gate1(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g
                    self.gates_layer[4][num_gates_4] = g
                    self.gate_id += 1
                    num_gates_4 += 1

                    n1.gate_in = g
                    n2.gate_in = g
                    n3.gate_out = g
                
                elif num_gates_2 < 2:

                    net_id_1 = tup[0]
                    net_id_2 = tup[1]
                    out_id   = tup[2]

                    if net_id_1 not in self.nets:
                        n1 = Net(net_id_1)
                        self.nets[net_id_1] = n1
                    else:
                        n1 = self.nets[net_id_1]
                    
                    if net_id_2 not in self.nets:
                        n2 = Net(net_id_2)
                        self.nets[net_id_2] = n2
                    else:
                        n2 = self.nets[net_id_2]

                    if out_id not in self.nets:
                        n3 = Net(out_id)
                        self.nets[out_id] = n3
                    else:
                        n3 = self.nets[out_id]

                    g = Gate1(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g
                    self.gates_layer[2][num_gates_2] = g
                    self.gate_id += 1
                    num_gates_2 += 1

                    n1.gate_in = g
                    n2.gate_in = g
                    n3.gate_out = g
                
                elif num_gates_1 < 1:

                    net_id_1 = tup[0]
                    net_id_2 = tup[1]
                    out_id   = tup[2]

                    if net_id_1 not in self.nets:
                        n1 = Net(net_id_1)
                        self.nets[net_id_1] = n1
                    else:
                        n1 = self.nets[net_id_1]
                    
                    if net_id_2 not in self.nets:
                        n2 = Net(net_id_2)
                        self.nets[net_id_2] = n2
                    else:
                        n2 = self.nets[net_id_2]

                    if out_id not in self.nets:
                        n3 = Net(out_id)
                        self.nets[out_id] = n3
                    else:
                        n3 = self.nets[out_id]

                    g = Gate1(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g
                    self.gates_layer[1][num_gates_1] = g
                    self.gate_id += 1
                    num_gates_1 += 1

                    n1.gate_in = g
                    n2.gate_in = g
                    n3.gate_out = g

            elif len(tup) == 2:

                net_id_1 = tup[0]
                out_id   = tup[1]

                if net_id_1 not in self.nets:
                    n1 = Net(net_id_1)
                    self.nets[net_id_1] = n1
                else:
                    n1 = self.nets[net_id_1]

                if out_id not in self.nets:
                    n2 = Net(out_id)
                    self.nets[out_id] = n2
                else:
                    n2 = self.nets[out_id]

                g = Gate2(self.gate_id, n1, n2)
                self.gates[self.gate_id] = g
                self.gate_id += 1

                n1.gate_in = g
                n2.gate_out = g

    def printList(self):
        l = []
        for gate_id in self.gates:
            gate = self.gates[gate_id]
            if gate.__class__.__name__ in ('Gate1'):
                w1 = gate.in1.net_id
                w2 = gate.in2.net_id
                w3 = gate.out.net_id
                tup = (w1, w2, w3)
                l.append(tup)
            else:
                w1 = gate.in1.net_id
                w2 = gate.out.net_id
                tup = (w1, w2)
                l.append(tup)
        print('Circuit in List Format:\n', l, '\n')



def getMenu(r):
    for _ in range(8):
        line = r.recvline().rstrip().decode()

def select(r, c):
    line = r.recvuntil(b': ')
    r.sendline(str(c).encode())

def insertFault(r, net_id, fault_val):
    getMenu(r)
    select(r, 1)
    r.recvuntil(b'on? ')
    r.sendline(str(net_id).encode())
    r.recvuntil(b'? ')
    r.sendline(str(fault_val).encode())
    line = r.recvline().rstrip().decode()
    assert(line.split(' ')[0] == 'Inserted')
    line = r.recvline().rstrip().decode()

def removeFault(r, net_id):
    getMenu(r)
    select(r, 2)
    r.recvuntil(b'from? ')
    r.sendline(str(net_id).encode())
    line = r.recvline().rstrip().decode()
    assert(line.split(' ')[0] == 'Removed')
    line = r.recvline().rstrip().decode()

def evaluate(r):
    getMenu(r)
    select(r, 3)
    line = r.recvline().rstrip().decode()
    output = int(line.split(' ')[1])
    line = r.recvline().rstrip().decode()
    return output

def DFS(circ, g, r, inputs, num_invs):

    if g.two_inputs == True:

        net_id1 = g.in1.net_id
        net_id2 = g.in2.net_id

        # Find gate type using fault injections
        gate_fingerprint = []

        # Apply 0,0 to the inputs of the gate
        insertFault(r, net_id1, 0)
        insertFault(r, net_id2, 0)
        out = evaluate(r)
        if num_invs % 2 == 0:
            gate_fingerprint.append(out)
        else:
            gate_fingerprint.append(out^1)

        # Apply 0,1 to the inputs of the gate
        removeFault(r, net_id2)
        insertFault(r, net_id2, 1)
        out = evaluate(r)
        if num_invs % 2 == 0:
            gate_fingerprint.append(out)
        else:
            gate_fingerprint.append(out^1)

        # Apply 1,0 to the inputs of the gate
        removeFault(r, net_id1)
        removeFault(r, net_id2)
        insertFault(r, net_id1, 1)
        insertFault(r, net_id2, 0)
        out = evaluate(r)
        if num_invs % 2 == 0:
            gate_fingerprint.append(out)
        else:
            gate_fingerprint.append(out^1)

        # Apply 1,1 to the inputs of the gate
        removeFault(r, net_id2)
        insertFault(r, net_id2, 1)
        out = evaluate(r)
        if num_invs % 2 == 0:
            gate_fingerprint.append(out)
        else:
            gate_fingerprint.append(out^1)

        # Remove faults from the inputs
        removeFault(r, net_id1)
        removeFault(r, net_id2)

        # Set gate type and inverting value
        g.type = gate_fingerprints[tuple(gate_fingerprint)]
        if inverting[g.type]:
            num_invs += 1

        # If we are at the input nets, find their values using the faults
        if g.in1.is_input:

            # Find input value on net 2
            insertFault(r, net_id1, sensitivities[g.type])
            input2 = evaluate(r)
            removeFault(r, net_id1)

            # Find input value on net 1
            insertFault(r, net_id2, sensitivities[g.type])
            input1 = evaluate(r)
            removeFault(r, net_id2)

            # Apply inversions as necessary
            if num_invs % 2 == 1:
                input2 = input2 ^ 1
                input1 = input1 ^ 1

            # Set the inputs
            for i in range(31, -1, -1):
                if inputs[i] == None:
                    inputs[i] = input2
                    inputs[i-1] = input1
                    break
        
        # Otherwise, set net 1 to sensitivity value and branch backwards to the gate connected to net 2.
        # Once that branch is finished recursing, do the same with the branch on net 1
        else:
            insertFault(r, net_id1, sensitivities[g.type])
            g2 = g.in2.gate_out
            DFS(circ, g2, r, inputs, num_invs)
            removeFault(r, net_id1)

            insertFault(r, net_id2, sensitivities[g.type])
            g2 = g.in1.gate_out
            DFS(circ, g2, r, inputs, num_invs)
            removeFault(r, net_id2)
    
    # For buffers/inverters, just move backwards (think about why we can do this... ;) )
    else:
        g2 = g.in1.gate_out
        DFS(circ, g2, r, inputs, num_invs)

# Connect to remote
r = remote('localhost', 1337)

# Receive opening quote
for _ in range(4):
    line = r.recvline().rstrip().decode()
    print(line)

# Store ciphertext
ciphertext = unhex(line.split(' ')[-1])

# Random line
line = r.recvline().rstrip().decode()
print(line)

# Stores the secret key
secret_chunks = []

# Iterate through the 14 circuits
for i in range(14):
    for _ in range(2):
        line = r.recvline().rstrip().decode()

    # Get the circuit as a list
    getMenu(r)
    select(r, 5)
    r.recvline().rstrip().decode()
    circuit_list = ast.literal_eval(r.recvline().rstrip().decode())
    circ = Circuit(circuit_list)

    # Start DFS and recover input bits
    out_gate = circ.gates_layer[1][0]
    inputs = [None]*32
    DFS(circ, out_gate, r, inputs, 0)
    s = ''.join([str(l) for l in inputs])
    secret_chunks.append(s)
    
    # Go to the next circuit
    getMenu(r)
    select(r, 6)

# Use the recovered secret to decrypt the flag
secret = ltb(int(''.join(secret_chunks), 2))
key = sha256(secret).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
print(f'Decrypted Flag: {flag}\n')

r.close()

# L3AK{F4uLt_1nJ3cti0N_C4n_M4k3_4NY_C1RCuIT_iN53cuRE!!-_-}
