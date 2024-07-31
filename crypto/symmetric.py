from Crypto.Cipher import ARC4, AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad





class RC4:
    def __init__(self, custom_key: str):
        self.cipher = ARC4.new(custom_key.encode())

    def encrypt(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).hex()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self.cipher.decrypt(bytes.fromhex(ciphertext)).decode()
        except ValueError:
            return 'Decrypt error'


class AESx:
    def __init__(self, custom_key: str, key_size=128):
        key_size = int(key_size / 8)
        self.key = pad(custom_key.encode(), int(key_size))[:key_size]

    def encrypt(self, data: str) -> str:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = pad(data.encode(), 16)
        return (iv + cipher.encrypt(plaintext)).hex()

    def decrypt(self, ciphertext: str) -> str:
        try:
            ciphertext = bytes.fromhex(ciphertext)
            iv = ciphertext[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[16:])
            plaintext = unpad(plaintext, 16)
            return plaintext.decode()
        except Exception:
            return 'Decrypt error'


class SingleDES:
    def __init__(self, custom_key: str):
        self.key = pad(custom_key.encode(), 8)[:8]

    def encrypt(self, data: str) -> str:
        iv = get_random_bytes(8)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        plaintext = pad(data.encode(), 8)
        return (iv + cipher.encrypt(plaintext)).hex()

    def decrypt(self, ciphertext: str) -> str:
        try:
            ciphertext = bytes.fromhex(ciphertext)
            iv = ciphertext[:8]
            cipher = DES.new(self.key, DES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[8:])
            plaintext = unpad(plaintext, 8)
            return plaintext.decode()
        except Exception:
            return 'Decrypt error'


class TripleDES:
    def __init__(self, custom_key: str):
        self.key = pad(custom_key.encode(), 24, style='x923')[:24]

    def encrypt(self, data: str) -> str:
        iv = get_random_bytes(8)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        plaintext = pad(data.encode(), 8)
        return (iv + cipher.encrypt(plaintext)).hex()

    def decrypt(self, ciphertext: str) -> str:
        try:
            ciphertext = bytes.fromhex(ciphertext)
            iv = ciphertext[:8]
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[8:])
            plaintext = unpad(plaintext, 8)
            return plaintext.decode()
        except Exception:
            return 'Decrypt error'
