# Henny on the rocks solution

Run the challenge PoC script:
```bash
python3 exploit.py <remote-host> <remote-port> <nsigs(Default: 100)>

python exploit.py 172.17.0.2 1337 80
```

The script will connect and receive $n$ signatures from the remote host then runs the attack defined in `utils.py` that solves the hidden number problem using an attack based on the shortest vector problem.
- The hidden number problem is defined as finding y such that {xi = {aij * yj} + bi mod m}.


... *To be continued*