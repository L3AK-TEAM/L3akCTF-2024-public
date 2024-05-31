# eXORbitant (Brief Solution)

In this challenge, we are given a Logisim circuit (http://www.cburch.com/logisim/) which takes 2-byte chunks of the flag and XORs the bits together in different combinations to generate an encrypted form. The flag is read from ROM and the encrypted version is written to RAM, and players are given the encrypted RAM output.

To solve this, we can simply use z3 to find the flag (it can handle large systems of XOR equations very well).
