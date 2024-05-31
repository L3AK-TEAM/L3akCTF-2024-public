library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity prng is
    port (
        clk       : in std_logic;
        reset     : in std_logic;
        enable    : in std_logic;
        init_seed : in unsigned(27 downto 0);
        prng_out  : out std_logic_vector(7 downto 0)
    );
end prng;

architecture behavior of prng is
    
    constant A : integer := 73067557;
    constant C : integer := 111837721;
    signal M : unsigned(63 downto 0);
    signal prng_reg : unsigned(63 downto 0);

begin
    process(clk, reset)
    variable seed : unsigned(63 downto 0);
    begin
        if reset = '1' then
            prng_reg <= (others => '0');
            prng_reg(27 downto 0) <= init_seed;
            M <= X"0000000010000000";
        elsif rising_edge(clk) then
            if enable = '1' then
                seed := (prng_reg * A + C) mod M;
                prng_reg <= seed;
            end if;
        end if;
    end process;

    prng_out <= std_logic_vector(prng_reg(27 downto 20));
end architecture;
