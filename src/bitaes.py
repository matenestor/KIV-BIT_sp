import sys
from hashlib import md5

import tables
from tables import MTX_M, BLOCK_SIZE, SBOX, RCON
from encrypt import aes_encrypt

ROUNDS = 9


def transpose(array):
    t = array[:]

    for i in range(MTX_M):
        for j in range(MTX_M):
            t[i + j*MTX_M] = array[i*MTX_M + j]

    return t


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
        return [a[ii] ^ b[ii] for ii in range(MTX_M)]

    # first 16 B of expanded key
    exp_key = key[:]

    # remaining 160 B of expanded key, one subkey in each i loop
    for i in range(1, ROUNDS+2):
        # subkey size
        sks = (i-1)*BLOCK_SIZE

        for j in range(MTX_M):
            # first 4 B of subkey
            if j == 0:
                last_col = expand_key_core(exp_key[-MTX_M:], i)
            # remaining 12 B of subkey
            else:
                last_col = exp_key[-MTX_M:]

            # exp_key.append(exp_key[-MTX_M:] ^ exp_key[j*MTX_M:(j+1)*MTX_M])
            exp_key += mxor(exp_key[j*MTX_M+sks:(j+1)*MTX_M+sks], last_col)

    return exp_key


def run(file_plain, file_cipher, expanded_key):
    block = file_plain.read(BLOCK_SIZE)

    while len(block) == BLOCK_SIZE:
        # encryption of middle blocks
        enc_block = aes_encrypt(bytearray(block), expanded_key, ROUNDS)
        file_cipher.write(enc_block)
        block = file_plain.read(BLOCK_SIZE)

    if len(block) % BLOCK_SIZE != 0 and len(block) != 0:
        block += bytes(BLOCK_SIZE - len(block))
        # encryption of final block
        enc_block = aes_encrypt(bytearray(block), expanded_key, ROUNDS)
        file_cipher.write(enc_block)


def main(fn_plain, fn_cipher, _key):
    try:
        with open(fn_plain, "rb") as file_plain:
            with open(fn_cipher, "wb") as file_cipher:
                # hash key to 128 bit
                key = md5(_key.encode()).digest()
                # sort by columns to 1D array
                key = transpose(list(key))
                expanded_key = expand_key(key)
                run(file_plain, file_cipher, bytes(expanded_key))

    except FileNotFoundError as e:
        print("{} [{}]".format(e.strerror, e.filename))
    # except:
    #     print("Unexpected error: {}".format(sys.exc_info()[0]))


if __name__ == '__main__':
    if len(sys.argv) > 3:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Not enough arguments.")
        print("Use: bitaes.py <plain-text-file-name> <file-w/cipher-name> <password>")
