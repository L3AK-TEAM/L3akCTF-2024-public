ghdl -a --std=08 --ieee=synopsys -fsynopsys prng.vhdl encrypt.vhdl
ghdl -e --std=08 --ieee=synopsys -fsynopsys encrypt
ghdl -r -g --std=08 --ieee=synopsys -fsynopsys encrypt
