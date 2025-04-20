import unittest
from rsa_cipher import generate_keys, encrypt, decrypt


class TestRSACipher(unittest.TestCase):

    def setUp(self):
        self.public_key, self.private_key = generate_keys()

    def test_encrypt_decrypt_basic(self):
        message = "The quick brown fox jumps"
        encrypted = encrypt(message, self.public_key)
        decrypted = decrypt(encrypted, self.private_key)
        self.assertEqual(decrypted, message)

    def test_encryption_is_deterministic(self):
        message = "Stay curious"
        encrypted1 = encrypt(message, self.public_key)
        encrypted2 = encrypt(message, self.public_key)
        self.assertEqual(encrypted1, encrypted2)  # Должно быть одинаково

    def test_decryption_with_wrong_key(self):
        message = "SecretMessage42"
        encrypted = encrypt(message, self.public_key)
        _, wrong_private = generate_keys()
        try:
            decrypted_wrong = decrypt(encrypted, wrong_private)
            self.assertNotEqual(decrypted_wrong, message)
        except ValueError:
            pass  # Ошибка допустима при неправильном ключе

    def test_ciphertext_is_not_plaintext(self):
        message = "test123"
        encrypted = encrypt(message, self.public_key)
        for i, ch in enumerate(message):
            self.assertNotEqual(ord(ch), encrypted[i])

    def test_large(self):
            msg = "DataBlock-" * 50  # 500+ символов
            encrypted = encrypt(msg, self.public_key)
            decrypted = decrypt(encrypted, self.private_key)
            self.assertEqual(decrypted, msg)

    def test_different_keys_same_message(self):
        message = "Never give up"
        pub2, priv2 = generate_keys()
        cipher1 = encrypt(message, self.public_key)
        cipher2 = encrypt(message, pub2)
        self.assertNotEqual(cipher1, cipher2)

    def test_known_encrypt_decrypt(self):
        pub = (17, 3233)  # Открытый ключ
        priv = (2753, 3233)  # Закрытый ключ
        encrypted = [encrypt(c, pub)[0] for c in "HELLO"]
        expected_encrypted = [3000, 28, 2726, 2726, 1307]
        self.assertEqual(encrypted, expected_encrypted)
        decrypted = ''.join([decrypt([c], priv) for c in encrypted])
        self.assertEqual(decrypted, "HELLO")


    def test_empty_string(self):
        encrypted = encrypt("", self.public_key)
        decrypted = decrypt(encrypted, self.private_key)
        self.assertEqual(decrypted, "")

    def test_nonletter_characters(self):
        msg = "#€@~§&^%$!*{}<>"
        encrypted = encrypt(msg, self.public_key)
        decrypted = decrypt(encrypted, self.private_key)
        self.assertEqual(decrypted, msg)

    def test_unicode(self):
        msg = "你好，世界"  # "Hello, World" на китайском
        encrypted = encrypt(msg, self.public_key)
        decrypted = decrypt(encrypted, self.private_key)
        self.assertEqual(decrypted, msg)
    
    def test_key_generation_different_keys(self):
        keys = set()
        for _ in range(6):
            pub, _ = generate_keys()
            keys.add(pub)
        self.assertGreater(len(keys), 1)

if __name__ == "__main__":
    unittest.main()
