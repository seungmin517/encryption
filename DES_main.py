import time
from Crypto.Cipher import DES
import os

def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)

def double_encrypt(plaintext, key1, key2):
    ciphertext = encrypt_des(plaintext, key1)
    return encrypt_des(ciphertext, key2)

# Generate random plaintext and keys
plaintext = os.urandom(10**6)  # 1MB plaintext
key1 = b"secret12"
key2 = b"double12"

# Measure time for DES encryption (1000 iterations)
print("Single DES encryption:")
des_times = []
for i in range(1000):
    start_time = time.time()
    encrypt_des(plaintext, key1)
    end_time = time.time()
    des_times.append(end_time - start_time)
    des_time_avg = sum(des_times) / len(des_times)
    progress = (i + 1) / 1000
    progress_bar = '#' * int(progress * 50)
    print("\r[{:50}] {:.2f}% | Current Time: {:.4f} seconds | Average Time: {:.4f} seconds".format(progress_bar, progress * 100, end_time - start_time, des_time_avg), end='', flush=True)
des_time_avg = sum(des_times) / len(des_times)

# Measure time for Double DES encryption (1000 iterations)
print("\n\nDouble DES encryption:")
double_des_times = []
for i in range(1000):
    start_time = time.time()
    double_encrypt(plaintext, key1, key2)
    end_time = time.time()
    double_des_times.append(end_time - start_time)
    double_des_time_avg = sum(double_des_times) / len(double_des_times)
    progress = (i + 1) / 1000
    progress_bar = '#' * int(progress * 50)
    print("\r[{:50}] {:.2f}% | Current Time: {:.4f} seconds | Average Time: {:.4f} seconds".format(progress_bar, progress * 100, end_time - start_time, double_des_time_avg), end='', flush=True)
double_des_time_avg = sum(double_des_times) / len(double_des_times)

# Calculate time difference ratio
time_difference_ratio_avg = double_des_time_avg / des_time_avg
print("\n\nOn average, Double DES encryption takes {:.2f} times longer than single DES encryption.".format(time_difference_ratio_avg))
