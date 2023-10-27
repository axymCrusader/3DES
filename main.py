from bitarray import bitarray
import tables
import secrets


def basic(permutation_table, to_permutate):
    permutated = bitarray()
    for i in permutation_table:
        permutated.append(to_permutate[i - 1])
    return permutated


def get_box_coordinates(_6bits):
    row = bin_to_dec(str(_6bits[0]) + str(_6bits[-1]))
    column = bin_to_dec(str(_6bits[1]) + str(_6bits[2]) + str(_6bits[3]) + str(_6bits[4]))
    return row, column


def sbox(input48):
    result32 = bitarray()
    chunks = split_bitarray_into_chunks(input48, 6)
    for i in range(8):
        row, column = get_box_coordinates(chunks[i])
        result32.extend(dec_to_bin(tables.SBOX[i][row][column]))
    return result32


def ascii_to_bin(text):
    result = bitarray()
    for c in text:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        while len(bits) < 8:
            bits = '0' + bits
        result.extend([int(b) for b in bits])
    return result

def dec_to_bin(dec):
    dec = bin(dec)[2:].zfill(4)
    binn = bitarray(str(dec))
    return binn

def bin_to_dec(binary):
    dec = int(str(binary), 2)
    return dec

def bin_to_ascii(binary):
    chars = split_bitarray_into_chunks(binary, 8)
    result = ""
    for i in range(len(chars)):
        char = chars[i].to01()
        result += chr(int(char, 2))
    return result

def hex_to_bin(array):
    dictionary = {
        '0': "0000",
        '1': "0001",
        '2': "0010",
        '3': "0011",
        '4': "0100",
        '5': "0101",
        '6': "0110",
        '7': "0111",
        '8': "1000",
        '9': "1001",
        'a': "1010",
        'b': "1011",
        'c': "1100",
        'd': "1101",
        'e': "1110",
        'f': "1111"}
    bin_output = bitarray()
    for i in range(len(array)):
        temp = bitarray(dictionary[array[i]])
        bin_output.extend(temp)
    return bin_output

def bin_to_hex(array):
    dictionary = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'a',
          "1011": 'b',
          "1100": 'c',
          "1101": 'd',
          "1110": 'e',
          "1111": 'f'}
    hex_output = ""
    for i in range(0, len(array), 4):
        temp = ""
        temp = temp + array[i]
        temp = temp + array[i + 1]
        temp = temp + array[i + 2]
        temp = temp + array[i + 3]
        hex_output = hex_output + dictionary[temp]
    return hex_output

def xor(bits1, bits2): 
    result = bitarray()
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]:
            result.append(0)
        else:
            result.append(1)
    return result


def split_string_into_chunks(to_split, chunk_size):
    how_many_chunks = len(to_split) // chunk_size
    left_over = len(to_split) % chunk_size
    index = 0
    text_chunks = list()
    chunk = ""
    for i in range(how_many_chunks):
        for j in range(chunk_size):
            chunk += to_split[index]
            index += 1
        text_chunks.append(chunk)
        chunk = ""
    if left_over != 0:
        for i in range(left_over):
            chunk += to_split[index + i]
        text_chunks.append(chunk)
    return text_chunks


def split_bitarray_into_chunks(to_split, chunk_size):
    how_many_chunks = len(to_split) // chunk_size
    left_over = len(to_split) % chunk_size
    index = 0
    list_of_xbits = list()
    chunk = bitarray()
    for i in range(how_many_chunks):
        for j in range(chunk_size):
            chunk.append(to_split[index])
            index += 1
        list_of_xbits.append(chunk.copy())
        chunk.clear()
    if left_over != 0:
        for i in range(left_over):
            chunk.append(to_split[index+i])
        list_of_xbits.append(chunk.copy())

    return list_of_xbits

def shift(key, number_of_bits):
    shifted_key = bitarray()
    i = 0
    while i < number_of_bits:
        shifted_key.append(key[i])
        i = i + 1
    i = 0
    while number_of_bits < len(key):
        key[i] = key[number_of_bits]
        i = i + 1
        number_of_bits = number_of_bits + 1
    key[:] = key[: i] + shifted_key
    return key


def split_in_half(to_split):
    half_length = int(len(to_split) / 2)
    l_half, r_half = to_split[:half_length], to_split[half_length:]
    return l_half, r_half

# генерация ключей 
def random_keys():
    keys = list()
    while len(keys) < 3:
        keys.append(''.join(secrets.token_hex(8)))
    return keys


def generate_keys(key64):
    keys = list()
    key56 = basic(tables.PC1, key64)
    left, right = split_in_half(key56)
    for roundnumber in range(16):
        newL = shift(left, tables.round_shifts[roundnumber])
        newR = shift(right, tables.round_shifts[roundnumber])
        key48 = basic(tables.PC2, newL + newR)
        keys.append(key48)
        left = newL
        right = newR
    return keys


def f_function(input32, key48):
    prepare48 = basic(tables.EXPANSION_TABLE, input32)
    prepare48 = xor(prepare48, key48)
    prepared32 = sbox(prepare48)
    result = basic(tables.PERMUTATION_TABLE, prepared32)
    return result


def des(message, key, mode):
    if mode == "e":
        message = ascii_to_bin(message) 
    bin_key = hex_to_bin(key)
    all_keys = generate_keys(bin_key)
    permutated_text = basic(tables.INITIAL_PERMUTATION_TABLE, message)
    left, right = split_in_half(permutated_text)
    for i in range(16):
        if mode == "e":
            new_r = xor(left, f_function(right, all_keys[i]))
        else:
            new_r = xor(left, f_function(right, all_keys[15 - i]))
        left = right
        right = new_r
    result = basic(tables.INVERSE_PERMUTATION_TABLE, right + left)
    if mode == "d":
        result = bin_to_ascii(result)
    return result
    

def triple_des_encryption(message, key1, key2, key3):
    if len(key1) < 8 or len(key2) < 8 or len(key3) < 8:
        raise ValueError("Wrong key length or no key specified!")
    encoded = bitarray()
    chunks64 = split_string_into_chunks(message, 8)
    padding_counter = 0
    while len(chunks64[-1]) < 8:
        chunks64[-1] += '0'
        padding_counter += 1

    padding_counter = str(padding_counter) + '0000000'
    chunks64.insert(0, padding_counter)
    for i in range(len(chunks64)):
        chunks64[i] = des(chunks64[i], key1, "e")
        chunks64[i] = des(chunks64[i], key2, "d")
        chunks64[i] = des(chunks64[i], key3, "e")
        encoded += chunks64[i]
    return encoded


def triple_des_decryption(encoded, key1, key2, key3):
    if len(key1) < 8 or len(key2) < 8 or len(key3) < 8:
        raise ValueError("Wrong key length or no key specified!")

    chunks64 = split_bitarray_into_chunks(encoded, 64)
    decoded = ""
    for i in range(len(chunks64)):
        chunks64[i] = des(chunks64[i], key1, "d")
        chunks64[i] = des(chunks64[i], key2, "e")
        chunks64[i] = des(chunks64[i], key3, "d")
        decoded += chunks64[i]
    padding_counter = decoded[:8]
    for i in range(int(padding_counter[0])):
        decoded = decoded[:-1]
    decoded = decoded[8:]
    return decoded


with open("D:\input.txt", "r") as f:
    text = f.read()
print(text)

keys = random_keys()

encrypted_text = triple_des_encryption(text, keys[0], keys[1], keys[0]).to01()
with open("D:\output.txt", "w") as f:
    f.write(encrypted_text)
print(encrypted_text)

decrypted_text = triple_des_decryption(bitarray(encrypted_text), keys[0], keys[1], keys[0])
with open("D:\output2.txt", "w") as f:
    f.write(decrypted_text)
print(decrypted_text)
