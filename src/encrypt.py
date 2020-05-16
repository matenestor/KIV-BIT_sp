import tables
from tables import MTX_M, BLOCK_SIZE, SBOX, GFMUL2, GFMUL3


def _sub_bytes(state):
    for i in range(BLOCK_SIZE):
        state[i] = SBOX[state[i]]


def _shift_rows(state):
    for i in range(1, MTX_M):
        idx = i*MTX_M

        # slice from the state
        row = state[idx:(i+1)*MTX_M]
        # shift the slice
        row = row[i:] + row[:i]

        # insert shifted values
        state[idx]   = row[0]
        state[idx+1] = row[1]
        state[idx+2] = row[2]
        state[idx+3] = row[3]


def _mix_columns(state):
    """ 2*a0 + a3 + a2 + 3*a1
        2*a1 + a0 + a3 + 3*a2
        2*a2 + a1 + a0 + 3*a3
        2*a3 + a2 + a1 + 3*a0
    """

    for i in range(MTX_M):
        idx = i*MTX_M

        state[idx]   = GFMUL2[state[idx]]   ^ state[idx+3] ^ state[idx+2] ^ GFMUL3[state[idx+1]]
        state[idx+1] = GFMUL2[state[idx+1]] ^ state[idx]   ^ state[idx+3] ^ GFMUL3[state[idx+2]]
        state[idx+2] = GFMUL2[state[idx+2]] ^ state[idx+1] ^ state[idx]   ^ GFMUL3[state[idx+3]]
        state[idx+3] = GFMUL2[state[idx+3]] ^ state[idx+2] ^ state[idx+1] ^ GFMUL3[state[idx]]


def _add_round_key(state, key):
    for i in range(BLOCK_SIZE):
        state[i] ^= key[i]


def aes_encrypt(state, key, rounds):
    enc_state = state[:]

    # first step
    _add_round_key(enc_state, key[:BLOCK_SIZE])

    # 9 middle rounds
    for i in range(1, rounds+1):
        _sub_bytes(enc_state)
        _shift_rows(enc_state)
        _mix_columns(enc_state)
        _add_round_key(enc_state, key[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE])

    # final round
    _sub_bytes(enc_state)
    _shift_rows(enc_state)
    _add_round_key(enc_state, key[-BLOCK_SIZE:])

    return enc_state
