import time

# 상수 테이블 정의
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2,
         1, 2, 2, 2, 2, 2, 2, 1]

#암호화 과정 상수 테이블
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]


# 치환 함수
def permute(block, table):
    return [block[x - 1] for x in table]


# 28비트 좌우 교환
def left_shift(key_chunk, shifts):
    return key_chunk[shifts:] + key_chunk[:shifts]

'''
def show_option(print_name, name, mode=True):
    if mode == 1:  #subkey 전용 출력 속성
        for i, subkey in enumerate(subkeys):
            print(f"Subkey {i + 1}: {''.join(map(str, subkey))}")
    else:
        print(f"{print_name}: {''.join(map(str, name))}")
    print(f"length of {print_name}: {len(name)}")
    print("====="*20+"\n")
    '''


def print_bit(arr):
    while len(arr) != 0:
        print(*arr[:8], sep=',')
        arr = arr[8:]


# 서브키 생성 함수
def gen_subkey(import_key):
    #show_option("initial key", import_key, False)

    # 64비트 키를 56비트로 변환
    permuted_key = permute(import_key, PC1)
    #show_option("permuted_key", permuted_key, False)

    # 좌우로 나누기
    C, D = permuted_key[:28], permuted_key[28:]
    #show_option("C", C, False)
    #show_option("D", D, False)

    # 16개의 서브키 생성
    subkey_list = []
    for shift in SHIFT:
        # 각 블록을 좌로 교환
        C = left_shift(C, shift)
        D = left_shift(D, shift)

        # 합치기
        combined_key = C + D

        # 48비트 키로 변환
        subkey_list.append(permute(combined_key, PC2))

    return subkey_list


def xor(t1, t2):
    return [x ^ y for x, y in zip(t1, t2)]


# 유틸리티 함수
def str_to_bit_array(text):
    bit_array = []
    for char in text:
        bin_value = bin(ord(char))[2:].zfill(8)  # 각 문자를 8비트 바이너리로 변환
        bit_array.extend(int(bit) for bit in bin_value)
    return bit_array


def bit_array_to_str(array):
    return ''.join(chr(int(''.join(map(str, array[i:i + 8])), 2)) for i in range(0, len(array), 8))


def sbox_substitution(expanded_half_block):
    sub_blocks = [expanded_half_block[i:i + 6] for i in range(0, len(expanded_half_block), 6)]
    result = []
    for i, block in enumerate(sub_blocks):
        row = int(f"{block[0]}{block[5]}", 2)
        col = int("".join(map(str, block[1:5])), 2)
        sbox_val = S_BOX[i][row][col]
        bin_val = bin(sbox_val)[2:].zfill(4)
        result.extend(int(bit) for bit in bin_val)
    return result


def f_function(right, subkey):
    expanded_right = permute(right, E)
    xor_result = xor(expanded_right, subkey)
    sbox_result = sbox_substitution(xor_result)
    return permute(sbox_result, P)


def des_encrypt_block(plaintext_block, subkeys):
    block = permute(plaintext_block, IP)
    #show_option("초기전치 후 블록", block, False)
    left, right = block[:32], block[32:]

    for subkey in subkeys:
        temp_right = right
        right = xor(left, f_function(right, subkey))
        left = temp_right

    combined_block = right + left
    cipher_block = permute(combined_block, IP_INV)
    return cipher_block


def des_decrypt_block(ciphertext_block, subkeys):
    # 암호화 블록에 초기 치환(IP)을 적용
    block = permute(ciphertext_block, IP)
    left, right = block[:32], block[32:]

    # 16 라운드 처리 (서브키를 역순으로 사용)
    for subkey in reversed(subkeys):
        temp_right = right
        right = xor(left, f_function(right, subkey))
        left = temp_right

    # 좌우 결합 후 최종 치환(IP_INV)을 적용
    combined_block = right + left
    plain_block = permute(combined_block, IP_INV)
    return plain_block


def input_text_and_keys(num):
    plaintext = input("Enter the plaintext: ")
    plaintext_bits = str_to_bit_array(plaintext)
    print("8비트 바이너리 배열로 변환한 평문: ")
    print_bit(plaintext_bits)
    print("====" * 20 + "\n")

    if len(plaintext_bits) % 64 != 0:
        print("평문의 비트 변환 결과가 64비트로 표현되지 않아 뒤에 0을 추가합니다.")
        while len(plaintext_bits) % 64 != 0:
            plaintext_bits += [0]
        print("0이 추가된 평문: ")
        print_bit(plaintext_bits)
        print("====" * 20 + "\n")

    if num == 1:
        key = input("Enter the 8-character key: ")
        key_bits = str_to_bit_array(key)

        return plaintext_bits, key_bits

    elif num == 2:
        key1 = input("Enter the first 8-character key: ")
        key2 = input("Enter the second 8-character key: ")
        key1_bits = str_to_bit_array(key1)
        key2_bits = str_to_bit_array(key2)

        return plaintext_bits, key1_bits, key2_bits


# 예시 실행
def sim_1DES():
    '''plaintext = input("Enter the plaintext: ")
    key = input("Enter the 8-character key: ")

    # key = "secret_k"  # 8 바이트 문자열을 64비트 비트 배열로 변환
    plaintext_bits = str_to_bit_array(plaintext)
    key_bits = str_to_bit_array(key)
    print("8비트 바이너리 배열로 변환한 평문: ")
    print_bit(plaintext_bits)
    print("===="*20+"\n")

    if len(plaintext_bits) % 64 != 0:
        print("평문의 비트 변환 결과가 64비트로 표현되지 않아 뒤에 0을 추가합니다.")
        while len(plaintext_bits) % 64 != 0:
            plaintext_bits += [0]
        print("0이 추가된 평문: ")
        print_bit(plaintext_bits)
        print("====" * 20 + "\n")'''

    plaintext_bits, key_bits = input_text_and_keys(1)

    start1 = time.time()  # 시작 시간 저장

    # 서브키 생성
    subkeys = gen_subkey(key_bits)
    #show_option("subkeys", subkeys, True)

    # 블록 암호화
    ciphertext_bits = []
    for i in range(0, len(plaintext_bits), 64):
        block = plaintext_bits[i:i + 64]
        encrypted_block = des_encrypt_block(block, subkeys)
        ciphertext_bits.extend(encrypted_block)

    # 암호문 비트 배열을 문자열로 변환
    ciphertext = bit_array_to_str(ciphertext_bits)

    print(f"Ciphertext: {ciphertext}")

    decrypted_bits = []
    for i in range(0, len(ciphertext_bits), 64):
        block = ciphertext_bits[i:i + 64]
        decrypted_block = des_decrypt_block(block, subkeys)
        decrypted_bits.extend(decrypted_block)

    # 복호문 비트 배열을 문자열로 변환
    decrypted_text = bit_array_to_str(decrypted_bits)

    print(f"Decrypted Text: {decrypted_text}")

    print("time :", time.time() - start1)  # 현재시각 - 시작시간 = 실행 시간


# 3DES 암호화
def triple_des_encrypt_block(plaintext_block, subkeys1, subkeys2):
    # Step 1: Encrypt with key1
    first_encrypt = des_encrypt_block(plaintext_block, subkeys1)
    # Step 2: Decrypt with key2
    first_decrypt = des_decrypt_block(first_encrypt, subkeys2)
    # Step 3: Encrypt again with key1
    final_encrypt = des_encrypt_block(first_decrypt, subkeys1)
    return final_encrypt


# 3DES 복호화
def triple_des_decrypt_block(ciphertext_block, subkeys1, subkeys2):
    # Step 1: Decrypt with key1
    first_decrypt = des_decrypt_block(ciphertext_block, subkeys1)
    # Step 2: Encrypt with key2
    first_encrypt = des_encrypt_block(first_decrypt, subkeys2)
    # Step 3: Decrypt again with key1
    final_decrypt = des_decrypt_block(first_encrypt, subkeys1)
    return final_decrypt


def sim_3DES():
    '''plaintext = input("Enter the plaintext: ")
    key1 = input("Enter the first 8-character key: ")
    key2 = input("Enter the second 8-character key: ")

    plaintext_bits = str_to_bit_array(plaintext)
    key1_bits = str_to_bit_array(key1)
    key2_bits = str_to_bit_array(key2)

    # Pad the plaintext bits to a multiple of 64 if necessary
    if len(plaintext_bits) % 64 != 0:
        print("Padding plaintext to 64 bits")
        while len(plaintext_bits) % 64 != 0:
            plaintext_bits += [0]'''

    plaintext_bits, key1_bits, key2_bits = input_text_and_keys(2)

    start2 = time.time()

    subkeys1 = gen_subkey(key1_bits)
    subkeys2 = gen_subkey(key2_bits)

    ciphertext_bits = []
    for i in range(0, len(plaintext_bits), 64):
        block = plaintext_bits[i:i + 64]
        encrypted_block = triple_des_encrypt_block(block, subkeys1, subkeys2)
        ciphertext_bits.extend(encrypted_block)

    ciphertext = bit_array_to_str(ciphertext_bits)
    print(f"Ciphertext: {ciphertext}")

    decrypted_bits = []
    for i in range(0, len(ciphertext_bits), 64):
        block = ciphertext_bits[i:i + 64]
        decrypted_block = triple_des_decrypt_block(block, subkeys1, subkeys2)
        decrypted_bits.extend(decrypted_block)

    decrypted_text = bit_array_to_str(decrypted_bits)
    print(f"Decrypted Text: {decrypted_text}")

    print("time :", time.time() - start2)  # 현재시각 - 시작시간 = 실행 시간


if __name__ == "__main__":
    sim_1DES()
    sim_3DES()
