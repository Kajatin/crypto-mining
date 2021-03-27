import hashlib
from struct import pack
from binascii import unhexlify, hexlify

from tqdm import tqdm


def int_to_hex_string(x):
    return hexlify(pack("<I", x)).decode("utf-8")

def block_hash_less_than_target(block_hash, given_target):
    return int(block_hash, 16) < int(given_target, 16)

def mine():
    # Preferred block version
    version = "01000000"
    # The hash of current highest block
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    # Hash of all the transactions in the block
    merkle_root = "3BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A"
    # The hash target
    target = "0x00000000FFFF0000000000000000000000000000000000000000000000000000"
    # Compressed current time
    time = "29AB5F49"
    # Compressed target of next block
    bits = "FFFF001D"
    # The maximum valid nonce (+1)
    max_nonce = 2**32

    # Pre-hash the static part of the block header
    hash_fn = hashlib.sha256()
    const_hdr = version + prev_hash + merkle_root + time + bits
    hash_fn.update(unhexlify(const_hdr))

    for nonce in tqdm(range(max_nonce)):
        # Hash the nonce into the header
        hash_fn_copy = hash_fn.copy()
        hash_fn_copy.update(unhexlify(int_to_hex_string(nonce)))
        digest = hash_fn_copy.digest()
        block_hash = hashlib.sha256(digest).digest()
        
        # Quick check if hash is potentially smaller than target
        if hexlify(block_hash)[-8:] != b'00000000':
            continue

        # Check if winning hash found
        block_hash_str = hexlify(block_hash[::-1]).decode("utf-8")
        if block_hash_less_than_target(block_hash_str, target):
            return block_hash_str, nonce

    return None, None

hash_str, nonce = mine()
if hash_str:
    print("Block mined with nonce: {}\n{}".format(nonce, hash_str))
    assert nonce == 2083236893, "incorrect nonce found"
else:
    print("Could not mine block... Maximum nonce reached")
