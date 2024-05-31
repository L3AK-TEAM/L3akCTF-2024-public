#!/usr/local/bin/python
from magika import Magika
from base64 import b64decode

inp = b64decode(input(">>> "))

magika = Magika()
indentification = magika.identify_bytes(inp)

dl = indentification.dl
output = indentification.output

if dl.ct_label != output.ct_label or dl.score <= 0.99 or output.score <= 0.99 or "python" in output.ct_label:
    print("Nope.")
    exit()

exec(inp, {"__builtins__": None})
