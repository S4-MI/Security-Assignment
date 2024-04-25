import numpy as np

from BitVector_Helper import perform_mix_column


def get_padded(text: str):
    if len(text) == 1:
        return f'0{text}'.upper()
    return text.upper()


def print_list(text: list):
    hex_text = [get_padded(str(hex(x))[2:]) for x in text]
    print(f"{hex_text}")


def print_matrix(matrix: np.array):
    row, col = matrix.shape
    for i in range(row):
        for j in range(col):
            print(f"{get_padded(str(hex(matrix[i][j]))[2:])}", end=" ")
        print()


Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

round_constants = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

fixed_matrix = np.array([
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
])


def g(w: list, round_number: int, debug=False):
    if debug:
        print('----------')
        print_list(w)
    # circular shift left
    w = w[1:] + w[:1]

    if debug:
        print_list(w)

    # byte substitution
    for i in range(4):
        w[i] = Sbox[w[i]]

    if debug:
        print_list(w)

    w[0] ^= round_constants[round_number]

    if debug:
        print_list(w)
    return w


def key_expansion(text: str, debug=False):
    # print(f"text len -> {len(text)}")

    hex_text = []
    for i in range(16):
        hex_text.append(ord(text[i]))
    words = hex_text

    keys = []
    for r in range(11):

        if r == 0:
            if debug:
                print(f"Words: ")
                for x in words:
                    print(str(hex(x))[2:], end=' ')
                print('')
            keys.append(words)
        else:
            temp = list(words.copy())
            last = list(temp[-4:])

            if debug:
                print_list(last)
            x = g(last, r - 1)

            if debug:
                print_list(x)

            temp += list(x ^ np.array(temp[-16:-12]))
            if debug:
                print(f'Temp: ')
                print_list(temp)
            temp += list(np.array(temp[-4:]) ^ np.array(temp[-16:-12]))
            temp += list(np.array(temp[-4:]) ^ np.array(temp[-16:-12]))
            temp += list(np.array(temp[-4:]) ^ np.array(temp[-16:-12]))

            if debug:
                print(f'Temp: ')
                print_list(temp)

            words = temp[16:]
            if debug:
                print(f"Words: ")
                for x in words:
                    print(str(hex(x))[2:], end=' ')
            keys.append(words)

    if debug:
        print(f"Keys: ")

    if debug:
        for i, key in enumerate(keys):
            print(f'Round {i}', end=' :')
            for x in key:
                t = str(hex(x))[2:]
                if len(t) == 1:
                    t = '0' + t
                print(f' {t}', end='')
            print('')

    return keys


def mix_column(matrix1: np.array, matrix2: np.array):
    result = np.zeros((4, 4), dtype=int)

    for i in range(4):
        for j in range(4):
            result[i][j] = perform_mix_column(
                [f'{str(hex(x))[2:]}' for x in matrix1[i]],
                [f'{str(hex(x))[2:]}' for x in matrix2[:, j]]
            )

    return result % 256


def sub_bytes(matrix: np.array):
    for i in range(4):
        matrix[i] = [Sbox[x] for x in matrix[i]]

    return matrix


def shift_rows(matrix: np.array):
    for i in range(1, 4):
        matrix[i] = np.roll(matrix[i], -i)

    return matrix


def add_round_key(matrix1: np.array, round_number: int, keys: list):
    key_matrix = np.array(keys[round_number]).reshape(4, 4).T
    return matrix1 ^ key_matrix


def AES(text: str, key: str, debug=False):
    if len(key) < 16:
        key += ' ' * (16 - len(key))

    key = key[-16:]

    keys = key_expansion(key, debug=debug)

    hex_text = []

    if len(text) < 16:
        text += ' ' * (16 - len(text))

    for i in range(16):
        hex_text.append(ord(text[i]))

    # create matrix
    text_matrix = np.array(hex_text).reshape(4, 4).T
    key_matrix_0 = np.array(keys[0]).reshape(4, 4).T
    result = text_matrix ^ key_matrix_0

    if debug:
        print_matrix(result)
        print('')

    results = [result.copy()]

    for i in range(1, 10):
        # sub bytes
        result = sub_bytes(result)

        if debug:
            print('\nSub Bytes')
            print_matrix(result)

        # shift rows
        result = shift_rows(result)

        if debug:
            print('\nShift Rows')
            print_matrix(result)

        # mix columns
        result = mix_column(fixed_matrix, result)

        if debug:
            print('\nMix Columns')
            print_matrix(result)

        # add round key

        result = add_round_key(result, i, keys)

        if debug:
            print('\nAdd Round Key')
            print_matrix(result)

        results.append(result.copy())

    # last round
    # sub bytes
    result = sub_bytes(result)

    if debug:
        print('\nSub Bytes')
        print_matrix(result)

    # shift rows
    result = shift_rows(result)

    if debug:
        print('\nShift Rows')
        print_matrix(result)

    # add round key
    result = add_round_key(result, 10, keys)

    results.append(result)

    if debug:
        print('\nAdd Round Key')
        print_matrix(result)

    if debug:
        print('Round outputs')
        for i in range(len(results)):
            print(f'Round {i}:', end=' ')
            l = []
            for j in range(4):
                for k in range(4):
                    print(f'{get_padded(str(hex(results[i][k][j]))[2:])}', end=' ')

            print('')

    cipher_text = ''
    for i in range(4):
        for j in range(4):
            val: int = results[-1][j][i]
            cipher_text += chr(val)

    # print('Key: ')
    # print(f'In Ascii: {key}')
    # print(f'In Hex: ', end='')
    # for c in key:
    #     print(f'{(str(hex(ord(c)))[2:])}', end='')
    # print('\n')

    # print('Text: ')
    # print(f'In Ascii: {text}')
    # print(f'In Hex: ', end='')
    # for c in text:
    #     print(f'{(str(hex(ord(c)))[2:])}', end='')
    # print('\n')

    # print(f'Cipher Text: {cipher_text}')
    # print(f'In Hex: ', end='')
    # for i in range(4):
    #     for j in range(4):
    #         print(f'{(str(hex(results[-1][j][i]))[2:])}', end='')

    return {
        'key': key,
        'text': text,
        'cipher_text': cipher_text
    }


def encrypt(text: str, key: str, debug=False):
    texts = []
    for i in range(0, len(text), 16):
        texts.append(text[i:i + 16])

    cipher_texts = []
    for t in texts:
        result = AES(t, key, debug)
        cipher_texts.append(result['cipher_text'])

    cipher_text = ''
    for c in cipher_texts:
        cipher_text += c

    print('Key: ')
    print(f'In Ascii: {key}')
    print(f'In Hex: ', end='')
    for c in key:
        print(f'{(str(hex(ord(c)))[2:])}', end='')
    print('\n')

    print('Text: ')
    print(f'In Ascii: {text}')
    print(f'In Hex: ', end='')
    for c in text:
        print(f'{(str(hex(ord(c)))[2:])}', end='')
    print('\n')

    print(f'Cipher Text: {cipher_text}')
    print(f'In Hex: ', end='')
    for c in cipher_text:
        print(f'{(str(hex(ord(c)))[2:])}', end='')


# result = encrypt(text='Two One Nine Two', key='Thats my Kung Fu', debug=False)
# result = encrypt(key='SUST CSE19 Batch', text='IsTheirCarnivalSuccessful', debug=False)
result = encrypt(key='SUST CSE19 Batch', text='YesTheyHaveMadeItAtLast', debug=False)
# result = encrypt(key='BUETCSEVSSUSTCSE', text='BUETnightfallVsSUSTguessforce', debug=False)


print('\n155415771458367c11457168f4059d618f1571f8e719bb2fbee5ebd6d3acf')
