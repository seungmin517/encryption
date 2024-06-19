from Crypto.Cipher import DES

def SHS_encrypt(plaintext, key):
    # DES의 라운드 수를 절반으로 줄임
    num_rounds = 8
    # DES 알고리즘 초기화
    cipher = DES.new(key, DES.MODE_ECB)
    # 암호문 생성
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def SHS_decrypt(ciphertext, key):
    # DES의 라운드 수를 절반으로 줄임
    num_rounds = 8
    # DES 알고리즘 초기화
    cipher = DES.new(key, DES.MODE_ECB)
    # 평문 복호화
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# 테스트를 위한 예시
plaintext = b"Hello, world!"
key = b"12345678"
ciphertext = SHS_encrypt(plaintext, key)
print("암호문:", ciphertext)
decrypted_text = SHS_decrypt(ciphertext, key)
print("복호문:", decrypted_text)
