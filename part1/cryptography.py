# install necessary cryptographic modules (1 point) 
# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.Hash import MD5 

# verify the hash of the following files:
# publickey.pem, part1.txt.enc, part1.txt.sig


# id file in file system
filename = "part1\part1.sha256"

# read the contents of the file 
with open(filename, "rb") as file:
    data = file.read()

# create a SHA-256 hash object 
hash_object = SHA256.new()

# feed the data into the hash object 
hash_object.update(data)

#retrieve the checksum as a hexadecimal string 
checksum = hash_object.hexdigest()

print("The SHA-256 checksum of", filename, "is:", checksum)
# decrypt the encrypted text file part1.txt.enc 
# use AES-128       the key sfhaCS2023



# verify the plaintext using the provided signature
# and public key (part1.txt.sig, publickey.pem)





# part 1 

# notes
# reference the cryptographic objects 
# (AESCrypto and RSACrypto) from Week 7 
# to help with encryption/ decryption 
