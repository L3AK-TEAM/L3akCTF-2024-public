import CryptoJS from 'crypto-js';

function keccak(arr) {
    return CryptoJS.SHA3(arr, { outputLength: 256 }).toString(CryptoJS.enc.Hex);
}

function getHash([position, character]) {
    const arr = CryptoJS.enc.Utf8.parse(String.fromCharCode(String(position)) + character);
    return keccak(arr);
}

function getFilteredNumbers(filter) {
    return Array.from({ length: 53 }, (_, i) => i).filter(num => !filter.includes(num));
}

function getCombinationHash(a, b) {
    [a, b] = [CryptoJS.enc.Hex.parse(a), CryptoJS.enc.Hex.parse(b)].sort();
    return keccak(a.concat(b)).toString('hex');
}

function generateCombinations(numbers) {
    const combinations = [];
    // Char codes for lowercase letters, uppercase letters, and numbers
    const charSets = [[97, 122], [65, 90], [48, 57]];
    for (let num of numbers) {
        for (let [start, end] of charSets) {
            for (let charCode = start; charCode <= end; charCode++) {
                combinations.push([num.toString(), String.fromCharCode(charCode)]);
            }
        }
    }
    return combinations;
}

// This is given in the initial proof
var leafs = [
    0x245f, 0x047b, 0x0f33, 0x0e33, 0x115f, 0x135f, 0x175f, 0x034b, 0x1575, 
    0x2a5f, 0x347d, 0x1b5f, 0x305f, 0x0b5f, 0x0241, 0x205f, 0x0133, 0x004c
].map(hex => {
    const hexString = hex.toString(16).padStart(4, '0');
    const byte1 = parseInt(hexString.substring(0, 2), 16).toString();
    const byte2 = String.fromCharCode(parseInt(hexString.substring(2), 16));
    return [byte1, byte2];
})

const found = leafs.map(([num]) => Number(num));
console.log(found)

function addCombination(combination) {
    leafs.push(combination);
    found.push(Number(combination[0]));
}

function printFlag() {
    const reconstructedStringArray = new Array(Math.max(...leafs.map(([num]) => parseInt(num))) + 1).fill('?');
    leafs.forEach(([position, letter]) => {
        const pos = parseInt(position);
        reconstructedStringArray[pos] = letter;
    });
    const reconstructedString = reconstructedStringArray.join('');
    console.log(reconstructedString);
}

const missingProofs = [
    '056598c127af600b14af0afc9ddc1c67198f9a7e25b71e5fd55faae8bbd36d86',
    '144ed2c9f6ff01fdf78e1cc644fe3d95a95fd2fe1ed77a58507f5da78ff05f20',
    '1e3b656119cc8baf71c42441183222ab3adf4d826f2882c53690cca6dad8d79f',
    '2980f1917103d13f85c6c303314adc45c39cfc2d7958c25c19bde11f1ce5a5ad',
    '4fe89595fdb35e1f5a3d9e229318b56fe182fd4cb9ad51a645a39e488114ec27',
    '541bc0a7a40a0befb9ddaf968806122968bcde23dd367c5ca8e4101021ff8780',
    '57e2cea585cf4b936d0c0f3b741c1c17f8a098bf629dfd6f3a94c86e7dad6de0',
    '67cadc87d41b9341d2d284afb1a5086419576225201cc422d8fa298c4a309604',
    '8a06f504ade0e8372e263666a8fb26858a76f13d622da423f7c003fca4131406',
    '9621a1df2013c8b2d578f74977a9a989db8b54291da69353363e1e342042786d',
    'cb7c375fbbd4f0c0d75424f64158d5b270acacb3e0d1be3e9cb20f92cf19ded8',
    'd4ff96ef079fcf74e735ab6edd089535eee307d39b0a52524f9bc2319c9c03b4',
    'da68cac114aa4dfd249caa3051829d198ef332bf118ff9246c13f6894314c2ce',
    'e00b3e132c8112490d164269b0390799900df47f44b2ad856030857c4dba014f',
    'fbf973526b06dab8d669d08bb6f07bb1cfb54c0ab011f7933592a420a4b8859b',
    '89b22b9ac564da8a828234aaa77ef9390e00193b115573d131d046873b575ca9',
    '403a7b8ace9ea6fcdd79886a1410ce955938f6e2f5e3650f815dcbaed4d2c3ce',
    'dcb24e0e84dea1b590e31e5c8b70925796f7daf2dee939ea61c7babe6523caf1',
    '94052ea1591c5d220aace09be5d8f716afeb1c57725e25782e714d7dbd5b49d3',
    '7d445306b69d3ecf86b5ed3bc7712d88f484e984e4e3fbe708bd891cf1140bf7',
    'f649e66155e7ec1e8a08db5e6c077d1890696157767b49c9ee8a5df0f9a8320f',
    '55f19ce476c13d483b0052fafc41375120e56cf99fefb53bd43ebb88fafd04e0',
    '0ffab6ee5eaa93cea0d097ff183236133b1fbdba56509454c8d23f05092b037e',
    '80787accc60ddad9832dbe33e0a73b81d0f4b7b5b8363af14e638671c20e6d27',
]

function findLeafs() {
    const numbers = getFilteredNumbers(found);
    const combinations = generateCombinations(numbers);
    combinations.forEach(combination => {
        const hash = getHash(combination);
        if (missingProofs.includes(hash)) {
            addCombination(combination);
            missingProofs.splice(missingProofs.indexOf(hash), 1);
        }
    });
}

function findBranch2() {
    const numbers = getFilteredNumbers(found);
    const combinations = generateCombinations(numbers);
    const hashes = combinations.map(getHash);
    hashes.forEach((hash1, index1) => {
        hashes.slice(index1 + 1).forEach((hash2, fakeindex) => {
            const index2 = index1 + 1 + fakeindex;
            const hash = getCombinationHash(hash1, hash2);
            if (missingProofs.includes(hash)) {
                addCombination(combinations[index1]);
                addCombination(combinations[index2]);
                missingProofs.splice(missingProofs.indexOf(hash), 1);
            }
        });
    });
}

function run(f) {
    console.log('Missing', missingProofs.length, 'proofs');
    const startTime = Date.now();
    f();
    const endTime = Date.now();
    const executionTime = (endTime - startTime) / 1000; // Convert milliseconds to seconds
    console.log("Execution time:", executionTime, "seconds");
    printFlag();
}

run(findLeafs);
run(findBranch2);

// L3AK{M3rk?3_Tr33s_R_FuN_8ut_wh47_4r?_th3s3_s4?ts_f?r}

const guesses = [
    [[9, 'l'], [35, 'e'], [45, 'l'], [50, 'o']],
    [[9, 'l'], [35, 'e'], [45, 'l'], [50, '0']],
    [[9, 'l'], [35, 'e'], [45, '1'], [50, 'o']],
    [[9, 'l'], [35, 'e'], [45, '1'], [50, '0']],
    [[9, 'l'], [35, '3'], [45, 'l'], [50, 'o']],
    [[9, 'l'], [35, '3'], [45, 'l'], [50, '0']],
    [[9, 'l'], [35, '3'], [45, '1'], [50, 'o']],
    [[9, 'l'], [35, '3'], [45, '1'], [50, '0']],
    [[9, '1'], [35, 'e'], [45, 'l'], [50, 'o']],
    [[9, '1'], [35, 'e'], [45, 'l'], [50, '0']],
    [[9, '1'], [35, 'e'], [45, '1'], [50, 'o']],
    [[9, '1'], [35, 'e'], [45, '1'], [50, '0']],
    [[9, '1'], [35, '3'], [45, 'l'], [50, 'o']],
    [[9, '1'], [35, '3'], [45, 'l'], [50, '0']],
    [[9, '1'], [35, '3'], [45, '1'], [50, 'o']],
    [[9, '1'], [35, '3'], [45, '1'], [50, '0']],
]

function getCombinations(arr) {
    const results = [];
    function generateCombinations(current, remaining) {
        if (remaining.length === 0) {
            results.push(current);
        } else {
            for (let i = 0; i < remaining.length; i++) {
                const next = current.concat([remaining[i]]);
                const rest = remaining.slice(0, i).concat(remaining.slice(i + 1));
                generateCombinations(next, rest);
            }
        }
    }
    generateCombinations([], arr);
    return results;
}

const shuffeledGuesses = guesses.flatMap(getCombinations);

for (const guess of shuffeledGuesses) {
    const hashes = guess.map(([position, character]) => getHash([position, character]));
    const combinationHashes = [0, 2].map(i => getCombinationHash(hashes[i], hashes[i + 1]));
    const hash = getCombinationHash(...combinationHashes);
    if (hash === '80787accc60ddad9832dbe33e0a73b81d0f4b7b5b8363af14e638671c20e6d27') {
        console.log("Correct guess");
        guess.forEach(addCombination);
        break;
    }
}

printFlag();
