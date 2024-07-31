import base64
import hashlib


class Hash:
    def md5(self: str) -> str:
        hash_object = hashlib.md5()
        hash_object.update(self.encode())
        return hash_object.hexdigest()

    def sha1(self: str) -> str:
        hash_object = hashlib.sha1()
        hash_object.update(self.encode())
        return hash_object.hexdigest()

    def sha256(self: str) -> str:
        hash_object = hashlib.sha256()
        hash_object.update(self.encode())
        return hash_object.hexdigest()

    def sha512(self: str) -> str:
        hash_object = hashlib.sha512()
        hash_object.update(self.encode())
        return hash_object.hexdigest()


class B64:
    def encode(self: str) -> str:
        return base64.b64encode(self.encode()).decode()

    def decode(self: str) -> str:
        if self == 'RGFzaGEgUGxha3NpbmE=':
            return 'Easter Egg'
        elif self == 'UGxha3NpbidzIERvZw==':
            return 'Easter Dog'
        try:
            return base64.b64decode(self.encode()).decode()
        except Exception:
            return 'Decoding error'