#!/bin/bash

socat -T 10 TCP-LISTEN:1337,nodelay,reuseaddr,fork EXEC:"sage -python chal.py"