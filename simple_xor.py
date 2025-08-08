import sys

# IMPORTANT: This must match the key used in the dumper script.
XOR_KEY = b"bobbert"

def decrypt_file(input_filename, output_filename):
    """Decrypts a file using a repeating XOR key."""
    if not XOR_KEY:
        print("Error: XOR_KEY is not set.")
        return

    try:
        with open(input_filename, 'rb') as f_in:
            xored_data = f_in.read()

        key_len = len(XOR_KEY)
        decrypted_data = bytes(xored_data[i] ^ XOR_KEY[i % key_len] for i in range(len(xored_data)))

        with open(output_filename, 'wb') as f_out:
            f_out.write(decrypted_data)

        print(f"Successfully decrypted '{input_filename}' to '{output_filename}'")

    except FileNotFoundError:
        print(f"Error: Input file not found: '{input_filename}'")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <encrypted_file> <output_file>")
        sys.exit(1)

    decrypt_file(sys.argv[1], sys.argv[2])

# Example Usage:
# python decrypt.py sam.xored SAM.hive
# python decrypt.py system.xored SYSTEM.hive
