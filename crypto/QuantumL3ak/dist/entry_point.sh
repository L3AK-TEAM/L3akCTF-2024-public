socat -T 10 TCP-LISTEN:31415,nodelay,reuseaddr,fork EXEC:"python3 quantum.py"
