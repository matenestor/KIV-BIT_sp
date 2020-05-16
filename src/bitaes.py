import sys
from hashlib import md5

import tables
from tables import MTX_M, BLOCK_SIZE, SBOX, RCON
from encrypt import aes_encrypt
from decrypt import aes_decrypt

ROUNDS = 10


def expand_key_core(col, idx):
    # rotate column
    c = col[1:] + col[:1]

    # sub bytes
    for i in range(MTX_M):
        c[i] = SBOX[c[i]]

    # rcon
    c[0] ^= RCON[idx]

    return c


def expand_key(key):
    def mxor(a, b):
        return bytearray([a[ii] ^ b[ii] for ii in range(MTX_M)])

    # first 16 B of expanded key
    exp_key = key[:]

    # remaining 160 B of expanded key, one subkey in each i loop
    for i in range(ROUNDS):
        # subkey size
        sks = i*BLOCK_SIZE

        for j in range(MTX_M):
            # first 4 B of subkey
            if j == 0:
                last_col = expand_key_core(exp_key[-MTX_M:], i+1)
            # remaining 12 B of subkey
            else:
                last_col = exp_key[-MTX_M:]

            # exp_key.append(exp_key[-MTX_M:] ^ exp_key[j*MTX_M:(j+1)*MTX_M])
            exp_key += mxor(exp_key[j*MTX_M+sks:(j+1)*MTX_M+sks], last_col)

    return exp_key


def run(file_read, file_write, expanded_key, aes_fce):
    block = file_read.read(BLOCK_SIZE)

    while len(block) == BLOCK_SIZE:
        # encryption of middle blocks
        enc_block = aes_fce(bytearray(block), expanded_key, ROUNDS)
        file_write.write(enc_block)
        block = file_read.read(BLOCK_SIZE)

    if len(block) % BLOCK_SIZE != 0 and len(block) != 0:
        block += bytes(BLOCK_SIZE - len(block))
        # encryption of final block
        enc_block = aes_fce(bytearray(block), expanded_key, ROUNDS)
        file_write.write(enc_block)


def main(mode, fn_read, fn_write, _key):
    try:
        with open(fn_read, "rb") as file_read:
            with open(fn_write, "wb") as file_write:
                # hash key to 128 bit
                key = md5(_key.encode()).digest()
                # key = _key.encode()  # line for school project

                # create subkeys
                expanded_key = expand_key(bytearray(key))

                # aes algorithm
                aes_fce = aes_encrypt if mode == "e" else aes_decrypt
                run(file_read, file_write, bytes(expanded_key), aes_fce)

    except FileNotFoundError as e:
        print("{} [{}]".format(e.strerror, e.filename))
    except:
        print("Unexpected error: {}".format(sys.exc_info()[0]))


if __name__ == '__main__':
    if len(sys.argv) > 4:

        if sys.argv[1] in ("e", "d"):
            main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

        else:
            print("Wrong argument for mode. [{}]".format(sys.argv[1]))
            print("Use: 'e' for encrypt\n     'd' for decrypt")

    else:
        print("Not enough arguments.")
        print("Use: bitaes.py <mode: e|d> <plain-text-file-name> <file-w/cipher-name> <password>")
