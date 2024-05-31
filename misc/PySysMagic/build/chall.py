# python3.10 chall.py build
# obligatory pyjail + PyMagic = ?

import os, sys
from distutils.core import Extension, setup

if "build" in sys.argv:
    if not os.path.exists("./audit_sandbox.so"):
        setup(
            name="audit_sandbox",
            ext_modules=[Extension("audit_sandbox", ["audit_sandbox.c"])],
        )
        os.popen("cp build/lib*/audit_sandbox* audit_sandbox.so")
    exit(0) 
    
code = input(">>> ")
import sys
import audit_sandbox

audit_sandbox.install_hook()
del audit_sandbox
del sys.modules["audit_sandbox"]
del sys

import re


class ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:
    ...  # ill be nice :)


eval = eval
if not re.findall("[()'\"0123456789 ]", code):
    for k in (b := __builtins__.__dict__).keys():
        b[k] = None

    eval(code, {"__builtins__": {}, "_": ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz})
else:
    print("Nope.")