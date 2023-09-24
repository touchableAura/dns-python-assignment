import hashlib 
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random
import base64

filename = "part1/part1.sha256"

with open(filename, 'rb') as f:
    bytes = f.read()
    hash_output = hashlib.md5(bytes).hexdigest();
    print("md5 hash of part1.sha256 file: " + hash_output)
    # md5 hash of file 883c62eec7c4463278031c9b2978794e


# separating / selecting hashes from file 
try:
    with open(filename, 'rt') as file:
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
    print(f"The file 'filename' was not found.")
except Exception as e:
    print(f"An error occurred: {e}")

# use hashlib to verify hashes from other files 
print(" hardcoded part1.txt.enc hash: acee06c7a8556e5b8ed42bea76c66dd642331f4c8831079f9e416d63918944ab ")
part1_enc = "part1/part1.txt.enc"
with open(part1_enc, 'rb') as f:
    bytes = f.read()
    hash_output = hashlib.md5(bytes).hexdigest();
    print("md5 hash of file: " + hash_output)


print(" hardcoded part1.txt.sig hash: 903bded47196a528c02f4cc34d5c2d43838d120aad4fb7548eb64459d4261d27")
part1_enc = "part1/part1.txt.sig"


h = hashlib.new("SHA256")
h.update(b"part1/part1.part1.sha256")

print(h.digest())
print(h.hexdigest())



# cs week 7 hashing 47:47

# create a SHA-256 hash object 
hash_object = SHA256.new()
hash_object.update("part1/part1.part1.sha256")

# return as a hexdecimal string  
