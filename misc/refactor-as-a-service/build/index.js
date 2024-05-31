
import readline from 'readline';
import { deobfuscate as refactor } from 'not-a-real-refactoring-tool';
import { Buffer } from 'buffer';

class Refactorer {
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        this.printBanner();

        this.rl.on('line', this.handleInput.bind(this));
        console.log("Welcome to Refactor as a Service!");
        console.log("Please enter your base64 encoded JavaScript code for processing:");
    }

    printBanner() {
        const BANNER =
            `
/$$$$$$$                       /$$$$$$ 
| $$__  $$                     /$$__  $$
| $$  \\ $$  /$$$$$$   /$$$$$$ | $$  \\__/
| $$$$$$$/ |____  $$ |____  $$|  $$$$$$ 
| $$__  $$  /$$$$$$$  /$$$$$$$ \\____  $$
| $$  \\ $$ /$$__  $$ /$$__  $$ /$$  \\ $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/
|__/  |__/ \\_______/ \\_______/ \\______/
`
        console.log(BANNER);
    }

    handleInput(input) {
        try {
            const decodedCode = this.decodeBase64(input);
            const refactoredCode = this.refactorCode(decodedCode);
            this.outputResult(refactoredCode);
        } catch (error) {
            console.error("Error during refactoring", error);
        } finally {
            this.rl.close();
            console.log("Goodbye!")
        }
    }

    decodeBase64(encoded) {
        return Buffer.from(encoded, 'base64').toString('utf-8');
    }

    refactorCode(decoded) {
        return refactor(decoded);
    }

    outputResult(refactoredCode) {
        console.log("Refactored Code:");
        console.log(refactoredCode);
    }
}

new Refactorer();

