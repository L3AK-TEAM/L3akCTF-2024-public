# ---------------------------- Libraries ------------------------------- #
import binascii


# ---------------------------- Classes ------------------------------- #

class Schiffy128:

    # Constractor
    def __init__(self, key_size=128, number_of_rounds=32):
        self.key_size = key_size
        self.number_of_rounds = number_of_rounds
        self.s_box = self.__create_8x8_s_box()

    # Methods
    @staticmethod
    def __create_8x8_s_box() -> list[int]:
        """
        Creates a 8x8 S-Box.
        :return: A list of integers representing the S-Box.
        """

        s_x = 170
        s_box = [170]

        for _ in range(255):
            s_x = ((37 * s_x) + 9) % 256
            s_box.append(s_x)

        return s_box

    @staticmethod
    def __split_into_blocks(message: str, block_size=32) -> list[str]:
        """
        Splits the message into blocks.
        :param message: The message to be split.
        :param block_size: The size of each block.
        :return: A list of strings representing the blocks.
        """

        if len(message) % block_size != 0:
            needed_padding = block_size - (len(message) % block_size)
            message = message + "2" * needed_padding

        blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]

        return blocks

    @staticmethod
    def __rotate_left(val: int, r_bits: int, max_bits: int) -> int:
        """
        Performs a left rotation.
        :param val: The value to be rotated.
        :param r_bits: The number of bits to rotate.
        :param max_bits: The maximum number of bits.
        :return: The result of the left rotation.
        """

        r_bits %= max_bits  # Ensure the rotation is within the maximum number of bits.
        mask = (1 << max_bits) - 1

        return ((val << r_bits) | (val >> (max_bits - r_bits))) & mask

    def key_schedule_algorithm(self, key: int, n_round_keys: int) -> list[str]:
        """
        Implements the key schedule algorithm.
        :param key: The key used in the algorithm.
        :param n_round_keys: The number of round keys.
        :return: A list of strings representing the round keys.
        """

        round_keys = []
        round_key = key

        for i in range(n_round_keys):
            round_key = (self.__rotate_left(round_key, 7 * i, 128)) ^ 0xabcdef
            round_keys.append(hex(round_key).lstrip("0x").zfill(32))

        return round_keys

    def feistel_function(self, block: int, round_key: int) -> str:
        """
        Implements the Feistel function.
        :param block: The block to be processed.
        :param round_key: The round key used in the function.
        :return: A string representing the result of the function.
        """

        round_key_high = round_key >> 64
        round_key_low = round_key & 0xFFFFFFFFFFFFFFFF

        block ^= round_key_high

        block_bytes = block.to_bytes(8, byteorder='big')
        new_block_bytes = bytearray()

        for byte in block_bytes:
            new_block_bytes.append(self.s_box[byte])

        block = int.from_bytes(new_block_bytes, byteorder='big')
        block ^= round_key_low

        return hex(block).lstrip("0x").zfill(16)

    def encrypt_decrypt(self, hex_message: str, hex_key: str, encrypt=True) -> str:
        """
        Performs the encryption and decryption function.
        :param hex_message: The message to be encrypted/decrypted.
        :param hex_key: The key used in the function.
        :param encrypt: A boolean indicating whether to encrypt (True) or decrypt (False).
        :return: A string representing the encrypted/decrypted message.
        """

        if 4 * len(hex_key) == self.key_size:
            hex_blocks = self.__split_into_blocks(hex_message)
            round_keys = self.key_schedule_algorithm(int(hex_key, 16), 32)
            new_message = ""

            for block in hex_blocks:
                left_block = block[:16]
                right_block = block[16:]

                if encrypt:
                    for i in range(self.number_of_rounds):
                        temp = right_block
                        feistel_output = self.feistel_function(int(right_block, 16), int(round_keys[i], 16))
                        result = hex(int(left_block, 16) ^ int(feistel_output, 16)).lstrip("0x").zfill(16)

                        left_block = temp
                        right_block = result

                    new_message += left_block + right_block

                else:
                    for i in reversed(range(self.number_of_rounds)):
                        temp = left_block
                        feistel_output = self.feistel_function(int(left_block, 16), int(round_keys[i], 16))
                        result = hex(int(right_block, 16) ^ int(feistel_output, 16)).lstrip("0x").zfill(16)

                        right_block = temp
                        left_block = result

                    new_message += left_block + right_block

            return new_message

        else:
            raise ValueError("The key size must be 128 bits.")


# ---------------------------- Functions ------------------------------- #
def string_to_hex(s):
    """
    Converts a string to hexadecimal.
    :param s: The string to be converted.
    :return: The hexadecimal representation of the string.
    """
    return binascii.hexlify(s.encode()).decode()


def hex_to_ascii(h):
    """
    Converts hexadecimal to a string.
    :param h: The hexadecimal to be converted.
    :return: The string representation of the hexadecimal.
    """
    return binascii.unhexlify(h.encode()).decode()


def create_binary_file(file_name: str, content: str):
    """
    Creates a binary file.
    :param file_name:
    :param content:
    :return:
    """
    with open(file_name, "wb") as f:
        f.write(bytes.fromhex(content))


def read_binary_file(file_name: str):
    """
    Reads a binary file.
    :param file_name:
    :return:
    """
    with open(file_name, "rb") as f:
        return f.read().hex()


def main():
    """
    Main function of the program.
    :return: None
    """

    schiffy = Schiffy128()

    key = "deadbeef000000000000000badc0ffee"

    binary_data = read_binary_file("../dev/ciphertext.bin")
    decrypted_message = schiffy.encrypt_decrypt(binary_data, key, False)
    smth = hex_to_ascii(decrypted_message)
    print(f"Decrypted message: {smth.encode()}")

# ------------------------------ Main ---------------------------------- #

if __name__ == "__main__":
    main()
