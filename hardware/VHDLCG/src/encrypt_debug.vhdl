library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use std.textio.all;
use ieee.std_logic_textio.all;

entity encrypt is
end encrypt;

architecture behavior of encrypt is
    signal clk : std_logic := '0';
    signal reset : std_logic := '1';
    signal enable : std_logic := '0';
    signal prng_out : std_logic_vector(7 downto 0);
    signal prng_key : std_logic_vector(319 downto 0);
    signal xor_result : std_logic_vector(319 downto 0);
    signal init_seed : unsigned(27 downto 0);
    constant clk_period : time := 10 ns;
    signal seed_out : unsigned(63 downto 0);

begin

    clk_process : process
    begin
        while now < 1 ms loop
            clk <= '0';
            wait for clk_period / 2;
            clk <= '1';
            wait for clk_period / 2;
        end loop;
        wait;
    end process;

    uut: entity work.prng
        port map (
            clk       => clk,
            reset     => reset,
            enable    => enable,
            init_seed => init_seed,
            prng_out  => prng_out,
            seed_out  => seed_out
        );

    process
        variable flag_value : std_logic_vector(319 downto 0);
        variable seed_value : std_logic_vector(27 downto 0);
        file flag_file : text open read_mode is "flag.txt";
        file seed_file : text open read_mode is "seed.txt";
        variable line_buffer : line;

    begin
        readline(flag_file, line_buffer);
        hread(line_buffer, flag_value);
        readline(seed_file, line_buffer);
        hread(line_buffer, seed_value);
        init_seed <= unsigned(seed_value);

        reset <= '1';
        wait for 20 ns;
        reset <= '0';

        enable <= '1';

        for i in 0 to 39 loop
            wait for clk_period;
            prng_key(((39-i)+1)*8-1 downto (39-i)*8) <= prng_out;
            report "LCG: " & to_hstring(prng_out);
            report "State: " & to_hstring(seed_out);
            report "Key: " & to_hstring(prng_key);
        end loop;
        wait for clk_period;

        xor_result <= flag_value xor prng_key;
        wait for clk_period;

        report "Encrypted Flag: " & to_hstring(xor_result);

        wait;
    end process;
end behavior;

