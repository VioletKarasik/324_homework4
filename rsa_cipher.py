import random
from math import gcd

def generate_primes(limit=10**6):
    """Генерация списка простых чисел до limit (решето Эратосфена)"""
    sieve = [True] * (limit + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = [False] * len(sieve[i*i::i])
    return [i for i, is_prime in enumerate(sieve) if is_prime]

# Глобальный список простых чисел
PRIMES = generate_primes()

def modinv(a, m):
    """Модулярная инверсия через расширенный алгоритм Евклида"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Обратный элемент не существует')
    return x % m

def extended_gcd(a, b):
    """Расширенный алгоритм Евклида"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def generate_keys():
    """Генерация ключевой пары RSA"""
    p = random.choice(PRIMES)
    q = random.choice(PRIMES)
    while q == p:
        q = random.choice(PRIMES)

    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Стандартное значение открытой экспоненты
    e = 65537
    if gcd(e, phi) != 1:
        e = 3  # Fallback для редких случаев
    
    d = modinv(e, phi)
    return ((e, n), (d, n))  # (public, private)

def encrypt(message, pub_key):
    """Шифрование сообщения"""
    e, n = pub_key
    if isinstance(message, str):
        message = message.encode('utf-8')
    return [pow(byte, e, n) for byte in message]

def decrypt(ciphertext, priv_key):
    """Дешифрование сообщения"""
    d, n = priv_key
    try:
        decrypted_bytes = bytes([pow(char, d, n) for char in ciphertext])
        return decrypted_bytes.decode('utf-8')
    except (UnicodeDecodeError, ValueError, OverflowError):
        raise ValueError("Decryption failed - invalid key or corrupted data")