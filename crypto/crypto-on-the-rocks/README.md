# Henny on the Rocks
- **Author**: [supaaasuge](https://github.com/supaaasuge)
- **Category**: Crypto
- **Difficulty**: Hard 
## Description
When life gives you biased nonces, put them on the rocks and drink them straight up. This challenge is like a stiff pour of cryptographic whiskey. No chaser.




## Build the container
```bash
cd henny-on-the-rocks/build
docker build -t henny-on-the-rocks .
```

## Run the container
```bash
docker run -p 7000:1337 -d henny-on-the-rocks .
```


### challenge - Served via socat
This version uses `socat` to serve the python script over a TCP connection on port `1337` 


##### backup version - SimpleThreadedTCP Server
`/backup/`