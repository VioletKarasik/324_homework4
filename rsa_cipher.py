import random
from math import gcd

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def get_prime_list(limit=10**6):
    primes = []
    sieve = [True] * (limit+1)
    sieve[0] = sieve[1] = False
    for p in range(2, limit+1):
        if sieve[p]:
            primes.append(p)
            for multiple in range(p*p, limit+1, p):
                sieve[multiple] = False
    return primes

def modinv(a, m):
    # Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys():
    primes = get_prime_list()
    p = random.choice(primes)
    q = random.choice(primes)
    while q == p:
        q = random.choice(primes)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.choice(primes)

    d = modinv(e, phi)
    return ((e, n), (d, n))  # public, private


def encrypt(message, pub_key):
    e, n = pub_key
    return [pow(ord(char), e, n) for char in message]

def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_chars = []
    for char in ciphertext:
        try:
            decrypted_char = chr(pow(char, d, n))
            decrypted_chars.append(decrypted_char)
        except ValueError:
            # Символ вне диапазона chr() — это значит дешифровка неверным ключом
            return "DECRYPTION_FAILED"
    return ''.join(decrypted_chars)

