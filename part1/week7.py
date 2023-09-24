from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random
import base64


# read 'part1.sha256' file contents 
# split into 3 lists (one for each line item)
# list (3) id hashes for each
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

        print("hash for publickey.pem:", hash_publickey)
        print("hash for encrypted text: ", hash_encrypted_text)
        print("hash for digital signature: ", hash_part1_txt_sig)

except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")
except Exception as e:
    print(f"An error occurred: {e}")


# decrypt the encrypted text file: part1.txt.enc  
# public key: sfhaCS2023

# classes

class CryptoAES:

    def md5_hash(self, text):   # make sure keysize is 128 bits 
        h = MD5.new()
        h.update(text.encode()) 
        return h.hexdigest()

    def __init__(self, key):           # initialize with password          
        self.key = self.md5_hash(key)  # hash the password (secret_key)

    def encrypt(self, cleartext):
        # block size should be equal to 128 bits
        Block_Size = AES.block_size 
        pad = lambda s: s + (Block_Size - len(s) % Block_Size) * chr(Block_Size - len(s) % Block_Size)
        cleartext_blocks = pad(cleartext)

        # create a random iv
        iv = Random.new().read(Block_Size)
        crypto = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        return base64.b64encode(iv + crypto.encrypt(cleartext_blocks.encode()))

    def decrypt(self, enctext):
        enctext = base64.b64decode(enctext)
        iv = enctext[:16]
        crypto = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        # Unpad the blocks before decrypting
        unpad = lambda s: s[:-ord(s[-1:])]
        return unpad(crypto.decrypt(enctext[16:]))

# aes = CryptoAES('password123')
# encrypted = aes.encrypt('Hello World')
# print("AES: ", encrypted)
# decrypted = aes.decrypt(encrypted)
# print("AES: ", decrypted)

class CryptoRSA:
    PRIVATE_KEY_FILE = "privatekey.pem"
    PUBLIC_KEY_FILE = "publickey.pem"

    def _save_file(self, contents, file_name):
        f = open(file_name, 'wb')  # Use 'wb' for bytes in Python 3
        f.write(contents)
        f.close()

    def _read_file(self, file_name):
        f = open(file_name, 'r')
        contents = f.read()
        f.close()
        return contents

    def generate_keys(self):
        keys = RSA.generate(4096)
        private_key = keys.exportKey("PEM")
        public_key = keys.publickey().exportKey("PEM")
        self._save_file(private_key, self.PRIVATE_KEY_FILE)
        self._save_file(public_key, self.PUBLIC_KEY_FILE)
        print("RSA update: Public & Private keys generated successfully!")

    def encrypt(self, cleartext, public_keypath=None):
        if public_keypath is None:
            public_keypath = self.PUBLIC_KEY_FILE
        public_key = RSA.importKey(self._read_file(public_keypath))
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher.encrypt(cleartext.encode())
        return base64.b64encode(encrypted_data)

    def decrypt(self, cipher_text, private_key_path=None):
        if private_key_path is None:
            private_key_path = self.PRIVATE_KEY_FILE

        cipher_text = base64.b64decode(cipher_text)
        private_key = RSA.importKey(self._read_file(private_key_path))
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(cipher_text)

# CryptoRSA().generate_keys()
# encrypted_data = CryptoRSA().encrypt("Hello World")
# print("RSA: ", encrypted_data)
# decrypted_data = CryptoRSA().decrypt(encrypted_data)
# print("RSA: ", decrypted_data)


# read file contents 



