# step 1: import nessesary modules
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

# step 2: verify the hashes 
file_path = 'part1.sha256'

try:
    with open(file_path, 'rt') as file:
        file_contents = file.read()
        content_list = file_contents.split('\n')

        # remove any empty lines 
        content_list = [line.strip() for line in content_list if line.strip()]

        # Assign variables
        public_key = content_list[0]
        encrypted_text = content_list[1]
        digital_signature = content_list[2]

        # Split the string on the space character
        public_key_items = public_key.split()
        encrypted_text_items = encrypted_text.split()
        digital_signature_items = digital_signature.split()

        # Remove spaces from each item and store them in a new list
        cleaned_public_key = [item.strip() for item in public_key_items]
        cleaned_encrypted_text = [item.strip() for item in encrypted_text_items]
        cleaned_digital_signature = [item.strip() for item in digital_signature_items]

        # make variables for each hash value individually
        hash_publickey = cleaned_public_key[1]
        hash_encrypted_text = cleaned_encrypted_text[1]
        hash_part1_txt_sig = cleaned_digital_signature[1]
        
        # List of file names
        file_names = ["part1.txt.enc", "part1.txt.sig"]

        # Expected hash values for comparison
        expected_hash_encrypted_text = hash_encrypted_text
        expected_hash_part1_txt_sig = hash_part1_txt_sig

        # Calculate and verify the hashes
        for file_name in file_names:
            with open(file_name, 'rb') as file:
                content = file.read()
                calculated_hash = hashlib.sha256(content).hexdigest()
                print(calculated_hash)

                if file_name == "part1.txt.enc" and calculated_hash == expected_hash_encrypted_text:
                    print(f"{file_name}: Hash verification passed.")
                elif file_name == "part1.txt.sig" and calculated_hash == expected_hash_part1_txt_sig:
                    print(f"{file_name}: Hash verification passed.")
                else:
                    print(f"{file_name}: Hash verification failed.")

except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")
except Exception as e:
    print(f"An error occurred: {e}")


# step3: decrypt the encrypted text file using AES-128

# Initialize the variable
encrypted_text = ""

# Specify the file path
file_path_enc_txt = 'part1.txt.enc'

try:
    with open(file_path_enc_txt, 'rb') as file:
        encrypted_text = file.read().decode('utf-8')

    # Print the encrypted text 
    print("Encrypted text:", encrypted_text)

except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")
except Exception as e:
    print(f"An error occurred: {e}")

class AESCrypto:
    def md5_hash(self, text):
        h = MD5.new()
        h.update(text.encode()) 
        return h.hexdigest()

    def __init__(self, key):         
        self.key = self.md5_hash(key) 

    def encrypt(self, cleartext):
        Block_Size = AES.block_size 
        pad = lambda s: s + (Block_Size - len(s) % Block_Size) * chr(Block_Size - len(s) % Block_Size)
        cleartext_blocks = pad(cleartext)

        iv = Random.new().read(Block_Size)
        crypto = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        return base64.b64encode(iv + crypto.encrypt(cleartext_blocks.encode()))

    def decrypt(self, enctext):
        enctext = base64.b64decode(enctext)
        iv = enctext[:16]
        crypto = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        # Unpad the blocks before decrypting
        unpad = lambda s: s[:-ord(s[-1:])]
        decrypted = crypto.decrypt(enctext[16:])
        return unpad(decrypted).decode('utf-8')  # Assuming the text is in UTF-8 encoding

aes = AESCrypto('sfhaCS2023')
decrypted = aes.decrypt(encrypted_text)
print("Decrypted text:", decrypted)
# print results: Keep up the great work!


# step 4: verify the plaintext
class CryptoRSA:
    PUBLIC_KEY_FILE = "publickey.pem"

    def __init__(self):
        return

    def generate_keys(self):
        # You can keep your key generation code here if needed
        pass

    def verify_signature(self, signature, plaintext):
        # Load the public key from 'publickey.pem'
        with open(self.PUBLIC_KEY_FILE, 'rb') as pubkey_file:
            public_key = RSA.import_key(pubkey_file.read())

        # Create a PKCS1_v1_5 signature object using the public key
        signature_verifier = PKCS1_v1_5.new(public_key)

        # Verify the signature
        is_verified = signature_verifier.verify(plaintext.encode('utf-8'), signature)

        if is_verified:
            print("Signature verification passed: The plaintext is authentic.")
        else:
            print("Signature verification failed: The plaintext is not authentic.")

# Example usage:
# Load the signature from 'part1.txt.sig' (you should have the signature as bytes)
with open('part1.txt.sig', 'rb') as sig_file:
    signature = base64.b64decode(sig_file.read())
    signature_encoded = base64.b64encode(signature_data)

# Load the decrypted plaintext from step 3
plaintext = decrypted  # Replace 'decrypted' with the actual decrypted text

# Create a CryptoRSA instance
rsa_crypto = CryptoRSA()

# Verify the signature using the public key from 'publickey.pem'
rsa_crypto.verify_signature(signature, plaintext)