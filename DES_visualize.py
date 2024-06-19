from Crypto.Cipher import DES
from collections import Counter

# DES에서 사용되는 약한 키
weak_keys = [
    b"\x01\x01\x01\x01\x01\x01\x01\x01",
    b"\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
    b"\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1"
    # 다른 약한 키들도 추가 가능
]

# DES 암호화 함수
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# 암호문에서 반복되는 비트 패턴 확인 함수
def find_repeating_bits(ciphertext):
    # 암호문을 이진 문자열로 변환
    binary_cipher = "".join(format(byte, '08b') for byte in ciphertext)
    # 암호문에서 반복되는 비트 패턴 추출
    repeating_bits = []
    for i in range(len(binary_cipher) - 1):
        if binary_cipher[i] == binary_cipher[i + 1]:
            repeating_bits.append((i, binary_cipher[i]))
    return repeating_bits

# 평문 정의 (바이트 문자열로 정의)
plaintext = b"01234567"

# 각 약한 키를 사용하여 DES 암호화 수행 및 반복되는 비트 패턴 확인
for idx, weak_key in enumerate(weak_keys):
    ciphertext = des_encrypt(plaintext, weak_key)
    print("Weak Key:", weak_key)
    repeating_bits = find_repeating_bits(ciphertext)
    if repeating_bits:
        print("Repeating bits pattern found:", repeating_bits)
    else:
        print("No repeating bits pattern found")
