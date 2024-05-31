import secrets

class Net:
    def __init__(self, net_id, val=None, is_input=False, input_val=None):
        self.net_id = net_id
        self.val = val
        self.stuck_at = False
        self.is_input = is_input
        self.input_val = input_val

class AND:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(self.in1.val and self.in2.val)

class NAND:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(not (self.in1.val and self.in2.val))

class OR:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(self.in1.val or self.in2.val)

class NOR:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(not (self.in1.val or self.in2.val))

class XOR:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(self.in1.val != self.in2.val)

class XNOR:
    def __init__(self, gate_id, in1, in2, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.in2 = in2
        self.out = out
        self.out_is_inv_buf = False

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(self.in1.val == self.in2.val)

class BUF:
    def __init__(self, gate_id, in1, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.out = out

    def op(self):
        if not self.out.stuck_at:
            self.out.val = self.in1.val

class INV:
    def __init__(self, gate_id, in1, out):
        self.gate_id = gate_id
        self.in1 = in1
        self.out = out

    def op(self):
        if not self.out.stuck_at:
            self.out.val = int(not self.in1.val)


class Circuit:

    def __init__(self, inputs):

        self.gates = {}
        self.nets = {}
        self.nets_layer = {}
        self.gates_layer = {}
        self.inputs = [int(i) for i in bin(inputs)[2:].zfill(32)]
        self.gate_types_1 = [AND, NAND, OR, NOR, XOR, XNOR]
        self.gate_types_2 = [INV, BUF]

        self.inv_buf_prob = 0.1
        self.net_id = 1
        self.gate_id = 1

        self.genCircuit()

    def genCircuit(self):

        for num_gates in (16, 8, 4, 2, 1):
            
            self.nets_layer[num_gates] = {}
            self.gates_layer[num_gates] = {}

            if num_gates == 16:
                for i in range(num_gates):

                    n1 = Net(self.net_id, self.inputs[i*2], True, self.inputs[i*2])
                    self.nets[self.net_id] = n1
                    self.net_id += 1

                    n2 = Net(self.net_id, self.inputs[i*2+1], True, self.inputs[i*2+1])
                    self.nets[self.net_id] = n2
                    self.net_id += 1

                    n3 = Net(self.net_id)
                    self.nets[self.net_id] = n3
                    self.net_id += 1

                    random_gate = secrets.choice(self.gate_types_1)
                    g1 = random_gate(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g1
                    self.gates_layer[num_gates][i] = g1
                    self.gate_id += 1

                    if secrets.randbelow(100) < self.inv_buf_prob * 100:

                        n4 = Net(self.net_id)
                        self.nets[self.net_id] = n4
                        self.net_id += 1

                        random_gate = secrets.choice(self.gate_types_2)
                        g2 = random_gate(self.gate_id, n3, n4)
                        self.gates[self.gate_id] = g2
                        self.gate_id += 1

                        g1.out_is_inv_buf = True
                        self.nets_layer[num_gates][i] = n4

                    else:
                        self.nets_layer[num_gates][i] = n3

            else:
                for i in range(num_gates):

                    n1 = self.nets_layer[num_gates*2][i*2]
                    n2 = self.nets_layer[num_gates*2][i*2+1]
                    n3 = Net(self.net_id)
                    self.nets[self.net_id] = n3
                    self.net_id += 1

                    random_gate = secrets.choice(self.gate_types_1)
                    g1 = random_gate(self.gate_id, n1, n2, n3)
                    self.gates[self.gate_id] = g1
                    self.gates_layer[num_gates][i] = g1
                    self.gate_id += 1

                    if num_gates != 1 and secrets.randbelow(100) < self.inv_buf_prob * 100:

                        n4 = Net(self.net_id)
                        self.nets[self.net_id] = n4
                        self.net_id += 1

                        random_gate = secrets.choice(self.gate_types_2)
                        g2 = random_gate(self.gate_id, n3, n4)
                        self.gates[self.gate_id] = g2
                        self.gate_id += 1

                        g1.out_is_inv_buf = True
                        self.nets_layer[num_gates][i] = n4

                    else:
                        self.nets_layer[num_gates][i] = n3


    def evaluate(self):
        for num_gates in (16, 8, 4, 2, 1):
            for i in range(num_gates):
                gate = self.gates_layer[num_gates][i]
                gate.op()
                if gate.out_is_inv_buf:
                    self.gates[gate.gate_id+1].op()
        output = self.nets_layer[1][0].val
        return output

    def insertFault(self, net_id, stuck_at_val):
        if net_id not in self.nets:
            return False
        if self.nets[net_id].stuck_at == True:
            return False
        if net_id == self.nets_layer[1][0].net_id:
            return False
        self.nets[net_id].stuck_at = True
        self.nets[net_id].val = stuck_at_val
        return True

    def removeFault(self, net_id):
        if net_id not in self.nets:
            return False
        if self.nets[net_id].stuck_at == False:
            return False
        self.nets[net_id].stuck_at = False
        if self.nets[net_id].is_input:
            self.nets[net_id].val = self.nets[net_id].input_val
        return True

    def printList(self):
        l = []
        for gate_id in self.gates:
            gate = self.gates[gate_id]
            if gate.__class__.__name__ in ('AND', 'NAND', 'OR', 'NOR', 'XOR', 'XNOR'):
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

    def printDiagram(self):
        circuit = f'''Visualization of the Circuit Structure:
==> G = Gate
====> For the big gates, G is one of AND/NAND/OR/NOR/XOR/XNOR
====> For the small gates (|G|), G is one of INV/BUF
==> Net numbers are also provided

         ___
---{self.gates_layer[16][0].in1.net_id:->2}---|   |     
        | G |---{self.gates_layer[16][0].out.net_id:->2}---{"|G|" if self.gates_layer[16][0].out_is_inv_buf else "---"}--|         ___
---{self.gates_layer[16][0].in2.net_id:->2}---|___|             |---{self.gates_layer[8][0].in1.net_id:->2}---|   |
         ___                       | G |---{self.gates_layer[8][0].out.net_id:->2}---{"|G|" if self.gates_layer[8][0].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][1].in1.net_id:->2}---|   |             |---{self.gates_layer[8][0].in2.net_id:->2}---|___|             |
        | G |---{self.gates_layer[16][1].out.net_id:->2}---{"|G|" if self.gates_layer[16][1].out_is_inv_buf else "---"}--|                          |         ___
---{self.gates_layer[16][1].in2.net_id:->2}---|___|                                        |---{self.gates_layer[4][0].in1.net_id:->2}---|   |
         ___                                                  | G |---{self.gates_layer[4][0].out.net_id:->2}---{"|G|" if self.gates_layer[4][0].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][2].in1.net_id:->2}---|   |                                        |---{self.gates_layer[4][0].in2.net_id:->2}---|___|             |
        | G |---{self.gates_layer[16][2].out.net_id:->2}---{"|G|" if self.gates_layer[16][2].out_is_inv_buf else "---"}--|         ___              |                          |
---{self.gates_layer[16][2].in2.net_id:->2}---|___|             |---{self.gates_layer[8][1].in1.net_id:->2}---|   |             |                          |
         ___                       | G |---{self.gates_layer[8][1].out.net_id:->2}---{"|G|" if self.gates_layer[8][1].out_is_inv_buf else "---"}--|                          |
---{self.gates_layer[16][3].in1.net_id:->2}---|   |             |---{self.gates_layer[8][1].in2.net_id:->2}---|___|                                        |
        | G |---{self.gates_layer[16][3].out.net_id:->2}---{"|G|" if self.gates_layer[16][3].out_is_inv_buf else "---"}--|                                                     |         ___
---{self.gates_layer[16][3].in2.net_id:->2}---|___|                                                                   |---{self.gates_layer[2][0].in1.net_id:->2}---|   |
         ___                                                                             | G |---{self.gates_layer[2][0].out.net_id:->2}---{"|G|" if self.gates_layer[2][0].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][4].in1.net_id:->2}---|   |                                                                   |---{self.gates_layer[2][0].in2.net_id:->2}---|___|             |
        | G |---{self.gates_layer[16][4].out.net_id:->2}---{"|G|" if self.gates_layer[16][4].out_is_inv_buf else "---"}--|         ___                                         |                          |
---{self.gates_layer[16][4].in2.net_id:->2}---|___|             |---{self.gates_layer[8][2].in1.net_id:->2}---|   |                                        |                          |
         ___                       | G |---{self.gates_layer[8][2].out.net_id:->2}---{"|G|" if self.gates_layer[8][2].out_is_inv_buf else "---"}--|                          |                          |
---{self.gates_layer[16][5].in1.net_id:->2}---|   |             |---{self.gates_layer[8][2].in2.net_id:->2}---|___|             |                          |                          |
        | G |---{self.gates_layer[16][5].out.net_id:->2}---{"|G|" if self.gates_layer[16][5].out_is_inv_buf else "---"}--|                          |         ___              |                          |
---{self.gates_layer[16][5].in2.net_id:->2}---|___|                                        |---{self.gates_layer[4][1].in1.net_id:->2}---|   |             |                          |
         ___                                                  | G |---{self.gates_layer[4][1].out.net_id:->2}---{"|G|" if self.gates_layer[4][1].out_is_inv_buf else "---"}--|                          |
---{self.gates_layer[16][6].in1.net_id:->2}---|   |                                        |---{self.gates_layer[4][1].in2.net_id:->2}---|___|                                        |
        | G |---{self.gates_layer[16][6].out.net_id:->2}---{"|G|" if self.gates_layer[16][6].out_is_inv_buf else "---"}--|         ___              |                                                     |
---{self.gates_layer[16][6].in2.net_id:->2}---|___|             |---{self.gates_layer[8][3].in1.net_id:->2}---|   |             |                                                     |
         ___                       | G |---{self.gates_layer[8][3].out.net_id:->2}---{"|G|" if self.gates_layer[8][3].out_is_inv_buf else "---"}--|                                                     |
---{self.gates_layer[16][7].in1.net_id:->2}---|   |             |---{self.gates_layer[8][3].in2.net_id:->2}---|___|                                                                   |
        | G |---{self.gates_layer[16][7].out.net_id:->2}---{"|G|" if self.gates_layer[16][7].out_is_inv_buf else "---"}--|                                                                                |         ___
---{self.gates_layer[16][7].in2.net_id:->2}---|___|                                                                                              |---{self.gates_layer[1][0].in1.net_id:->2}---|   |
         ___                                                                                                        | G |----- Output
---{self.gates_layer[16][8].in1.net_id:->2}---|   |                                                                                              |---{self.gates_layer[1][0].in2.net_id:->2}---|___|
        | G |---{self.gates_layer[16][8].out.net_id:->2}---{"|G|" if self.gates_layer[16][8].out_is_inv_buf else "---"}--|         ___                                                                    |
---{self.gates_layer[16][8].in2.net_id:->2}---|___|             |---{self.gates_layer[8][4].in1.net_id:->2}---|   |                                                                   |
         ___                       | G |---{self.gates_layer[8][4].out.net_id:->2}---{"|G|" if self.gates_layer[8][4].out_is_inv_buf else "---"}--|                                                     |
---{self.gates_layer[16][9].in1.net_id:->2}---|   |             |---{self.gates_layer[8][4].in2.net_id:->2}---|___|             |                                                     |
        | G |---{self.gates_layer[16][9].out.net_id:->2}---{"|G|" if self.gates_layer[16][9].out_is_inv_buf else "---"}--|                          |         ___                                         |
---{self.gates_layer[16][9].in2.net_id:->2}---|___|                                        |---{self.gates_layer[4][2].in1.net_id:->2}---|   |                                        |
         ___                                                  | G |---{self.gates_layer[4][2].out.net_id:->2}---{"|G|" if self.gates_layer[4][2].out_is_inv_buf else "---"}--|                          |
---{self.gates_layer[16][10].in1.net_id:->2}---|   |                                        |---{self.gates_layer[4][2].in2.net_id:->2}---|___|             |                          |
        | G |---{self.gates_layer[16][10].out.net_id:->2}---{"|G|" if self.gates_layer[16][10].out_is_inv_buf else "---"}--|         ___              |                          |                          |
---{self.gates_layer[16][10].in2.net_id:->2}---|___|             |---{self.gates_layer[8][5].in1.net_id:->2}---|   |             |                          |                          |
         ___                       | G |---{self.gates_layer[8][5].out.net_id:->2}---{"|G|" if self.gates_layer[8][5].out_is_inv_buf else "---"}--|                          |                          |
---{self.gates_layer[16][11].in1.net_id:->2}---|   |             |---{self.gates_layer[8][5].in2.net_id:->2}---|___|                                        |                          |
        | G |---{self.gates_layer[16][11].out.net_id:->2}---{"|G|" if self.gates_layer[16][11].out_is_inv_buf else "---"}--|                                                     |         ___              |
---{self.gates_layer[16][11].in2.net_id:->2}---|___|                                                                   |---{self.gates_layer[2][1].in1.net_id:->2}---|   |             |
         ___                                                                             | G |---{self.gates_layer[2][1].out.net_id:->2}---{"|G|" if self.gates_layer[2][1].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][12].in1.net_id:->2}---|   |                                                                   |---{self.gates_layer[2][1].in2.net_id:->2}---|___|
        | G |---{self.gates_layer[16][12].out.net_id:->2}---{"|G|" if self.gates_layer[16][12].out_is_inv_buf else "---"}--|         ___                                         |
---{self.gates_layer[16][12].in2.net_id:->2}---|___|             |---{self.gates_layer[8][6].in1.net_id:->2}---|   |                                        |
         ___                       | G |---{self.gates_layer[8][6].out.net_id:->2}---{"|G|" if self.gates_layer[8][6].out_is_inv_buf else "---"}--|                          |
---{self.gates_layer[16][13].in1.net_id:->2}---|   |             |---{self.gates_layer[8][6].in2.net_id:->2}---|___|             |                          |
        | G |---{self.gates_layer[16][13].out.net_id:->2}---{"|G|" if self.gates_layer[16][13].out_is_inv_buf else "---"}--|                          |         ___              |
---{self.gates_layer[16][13].in2.net_id:->2}---|___|                                        |---{self.gates_layer[4][3].in1.net_id:->2}---|   |             |
         ___                                                  | G |---{self.gates_layer[4][3].out.net_id:->2}---{"|G|" if self.gates_layer[4][3].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][14].in1.net_id:->2}---|   |                                        |---{self.gates_layer[4][3].in2.net_id:->2}---|___|
        | G |---{self.gates_layer[16][14].out.net_id:->2}---{"|G|" if self.gates_layer[16][14].out_is_inv_buf else "---"}--|         ___              |
---{self.gates_layer[16][14].in2.net_id:->2}---|___|             |---{self.gates_layer[8][7].in1.net_id:->2}---|   |             |
         ___                       | G |---{self.gates_layer[8][7].out.net_id:->2}---{"|G|" if self.gates_layer[8][7].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][15].in1.net_id:->2}---|   |             |---{self.gates_layer[8][7].in2.net_id:->2}---|___|
        | G |---{self.gates_layer[16][15].out.net_id:->2}---{"|G|" if self.gates_layer[16][15].out_is_inv_buf else "---"}--|
---{self.gates_layer[16][15].in2.net_id:->2}---|___|       
        
        '''
        print(circuit)

