from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# create variables
part1_enc_file = "part1\part1.txt.enc"
part1_sig_file = "part1\part1.txt.sig"

def verify_hash(filename):

    
    filename.encode()

    # create SHA-256 hash object
    hash_object = SHA256.new()
    hash_object.update()

    # get the hash for comparison
    input_hashed_password = hash_object.hexdigest()

    print("hardcoded:")
    print("acee06c7a8556e5b8ed42bea76c66dd642331f4c8831079f9e416d63918944ab")
    print("function generated:")
    print(input_hashed_password)

verify_hash(part1_enc_file)