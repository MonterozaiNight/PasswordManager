from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

class Credentials():

    def __init__(self):
        self.__username = ""
        self.__password = ""

    def generate_keys(self, passphrase):
        # 秘密鍵を生成
        private_key = self.create_private_key(passphrase)
        # 公開鍵を生成
        public_key = self.create_public_key(private_key, passphrase)
        ## 秘密鍵と公開鍵をファイルに保存
        self.save_keys_to_files(private_key, public_key)

    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, value):
        self.__username = value

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, value):
        self.__password = value

    def create_private_key(self, passphrase):
        # 秘密鍵を生成
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # 秘密鍵をPEM形式でエクスポートし、パスフレーズで暗号化
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )

        return private_pem

    def create_public_key(self, private_key, passphrase):
        # 秘密鍵から公開鍵を取得
        private_key = serialization.load_pem_private_key(
            private_key,
            password=passphrase.encode()
        )
        public_key = private_key.public_key()

        # 公開鍵をPEM形式でエクスポート
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_pem

    def save_keys_to_files(self, private_key, public_key, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        # 秘密鍵をファイルに保存
        with open(private_key_path, "wb") as private_file:
            private_file.write(private_key)

        # 公開鍵をファイルに保存
        with open(public_key_path, "wb") as public_file:
            public_file.write(public_key)

    def encrypt_password(self, public_key_path = "public_key.pem"):
        # 公開鍵ファイルを読み込んで、公開鍵を取得
        with open(public_key_path, "rb") as public_file:
            public_key = serialization.load_pem_public_key(public_file.read())

        # 公開鍵を使ってパスワードを暗号化
        encrypted_password = public_key.encrypt(
            self.__password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_password

    def decrypt_password(self, passphrase, encrypted_password_bytes, private_key_path = "private_key.pem"):
        # 秘密鍵を読み込む
        with open(private_key_path, "rb") as private_file:
            private_pem = serialization.load_pem_private_key(private_file.read(), password=passphrase.encode())

        # 秘密鍵を使って暗号化されたパスワードを復号化
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=passphrase.encode()
        )

        decrypted_password = private_key.decrypt(
            encrypted_password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_password.decode()

    def encrypted_passphrase(self, passphrase, user_password, salt):
        ### マスターパスワードとソルトからFernet用の32バイトの暗号化キーを生成
        key = self.derive_key(user_password, salt)
        cipher = Fernet(key)

        return cipher.encrypt(passphrase.encode())

    def decrypted_passphrase(self, encrypted_data, user_password, salt):
        try:
            # マスターパスワードとソルトを使って鍵を生成
            key = self.derive_key(user_password, salt)
            cipher = Fernet(key)

            # 復号する
            decrypted_passphrase = cipher.decrypt(encrypted_data).decode()
            print("復号成功！ パスフレーズを取得できました。")
            return decrypted_passphrase
        except Exception:
            print("エラー: パスワードが違うか、データが破損しています。")
            return None

    def derive_key(self, user_password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )

        return base64.urlsafe_b64encode(kdf.derive(user_password.encode()))