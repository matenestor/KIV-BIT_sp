import tables
from tables import MTX_M, BLOCK_SIZE, SBOX_INV, GFMUL9, GFMUL11, GFMUL13, GFMUL14


def _sub_bytes(state):
    for i in range(BLOCK_SIZE):
        state[i] = SBOX_INV[state[i]]


def _shift_rows(state):
    for i in range(1, MTX_M):
        # slice from the state
        row = [state[i+j*MTX_M] for j in range(MTX_M)]

        # shift the slice to the right
        row = row[-i:] + row[:-i]

        # insert shifted values
        for j in range(MTX_M):
            state[i+j*MTX_M] = row[j]


def _mix_columns(state):
    """ 14*a0 + 9*a3 + 13*a2 + 11*a1
        14*a1 + 9*a0 + 13*a3 + 11*a2
        14*a2 + 9*a1 + 13*a0 + 11*a3
        14*a3 + 9*a2 + 13*a1 + 11*a0
    """

    mult = [0 for _ in range(MTX_M)]

    for i in range(MTX_M):
        idx = i*MTX_M

        # multiplicate
        mult[0] = GFMUL14[state[idx]]   ^ GFMUL9[state[idx+3]] ^ GFMUL13[state[idx+2]] ^ GFMUL11[state[idx+1]]
        mult[1] = GFMUL14[state[idx+1]] ^ GFMUL9[state[idx]]   ^ GFMUL13[state[idx+3]] ^ GFMUL11[state[idx+2]]
        mult[2] = GFMUL14[state[idx+2]] ^ GFMUL9[state[idx+1]] ^ GFMUL13[state[idx]]   ^ GFMUL11[state[idx+3]]
        mult[3] = GFMUL14[state[idx+3]] ^ GFMUL9[state[idx+2]] ^ GFMUL13[state[idx+1]] ^ GFMUL11[state[idx]]

        # insert multiplicated values
        for j in range(MTX_M):
            state[idx+j] = mult[j]


def _add_round_key(state, key):
    for i in range(BLOCK_SIZE):
        state[i] ^= key[i]


def aes_decrypt(state, key, rounds):
    dec_state = state[:]

    # first inverse step
    _add_round_key(dec_state, key[-BLOCK_SIZE:])
    _shift_rows(dec_state)
    _sub_bytes(dec_state)

    # 9 middle inverse rounds
    for i in range(1, rounds):
        _add_round_key(dec_state, key[(rounds-i)*BLOCK_SIZE:(rounds-i+1)*BLOCK_SIZE])
        _mix_columns(dec_state)
        _shift_rows(dec_state)
        _sub_bytes(dec_state)

    # final inverse round
    _add_round_key(dec_state, key[:BLOCK_SIZE])

    return dec_state
