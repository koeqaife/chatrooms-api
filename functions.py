# 1.3
import os
import string
import aiosqlite
import random
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import asyncio
import hmac
from cryptography.fernet import Fernet


encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

key_file = ".secret_key.txt"


def generate_and_save_secret_key(file_path: str, length: int = 32) -> None:
    if not os.path.exists(file_path):
        secret_key = os.urandom(length)
        with open(file_path, 'wb') as file:
            file.write(secret_key)


def read_secret_key(file_path: str) -> bytes:
    with open(file_path, 'rb') as file:
        secret_key = file.read()
    return secret_key


generate_and_save_secret_key(key_file)

secret_key = read_secret_key(key_file)


def generate_random_word(length) -> str:
    pattern = r'^[0-9a-z.#]+$'
    length = length
    regex_pattern = re.compile(pattern)
    vowels = 'aeiou'
    consonants = 'bcdfghjklmnpqrstvwxyz'
    word = ''

    while not regex_pattern.match(word):
        word = ''
        vowel_count = 0
        consonant_count = 0
        last_vowel = ''

        while len(word) < length:
            rand = random.randint(1, 2)

            if rand == 1:
                if vowel_count >= 2:
                    continue
                else:
                    vowel = random.choice([v for v in vowels if v != last_vowel])
                    last_vowel = vowel
                    vowel_count += 1
                    consonant_count = 0
                    word += vowel
            elif rand == 2:
                if consonant_count >= 1:
                    continue
                else:
                    consonant_count += 1
                    vowel_count = 0
                    word += random.choice(consonants)

        for _ in range(int(length/20)):
            index = random.randint(2, length-6)
            symbol = "."
            word = word[:index] + symbol + word[index+1:]
        index = length-5

    return word


def sha256(string: str) -> str:
    return hmac.new(secret_key, string.encode(), hashlib.sha256).hexdigest()


def sha512(string: str) -> str:
    return hmac.new(secret_key, string.encode(), hashlib.sha512).hexdigest()


def generate_passphrase(count, min_length, max_length) -> str:
    list = [generate_random_word(random.randint(min_length, max_length)) for _ in range(count)]
    return ' '.join(list)


def generate_rsa_key(passphrase: str) -> tuple[bytes, bytes]:
    passphrase = sha512(passphrase)
    key = RSA.generate(2048)
    encrypted_key = key.export_key(passphrase=passphrase, pkcs=8,
                                   protection="scryptAndAES128-CBC")
    public_key = key.publickey().export_key(passphrase=passphrase, pkcs=8,
                                            protection="scryptAndAES128-CBC")
    return encrypted_key, public_key


def generate_aes_key() -> bytes:
    return os.urandom(32)


def aes_encrypt(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes)  # type: ignore


def aes_decrypt(encrypted_message: bytes, key: bytes) -> bytes:
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    ct = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def encrypt_message(message: bytes | str, public_key: bytes | str, passphrase: str) -> str:
    if isinstance(message, str):
        message = message.encode()
    if isinstance(public_key, str):
        public_key = public_key.encode()
    _passphrase = sha512(passphrase)

    aes_key = generate_aes_key()

    encrypted_message = aes_encrypt(message, aes_key)

    imported_public_key = RSA.import_key(public_key, passphrase=_passphrase)
    cipher_rsa = PKCS1_OAEP.new(imported_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key + encrypted_message).decode()


def decrypt_message(encrypted_message: str | bytes, private_key: bytes | str, passphrase: str) -> str:
    if isinstance(encrypted_message, str):
        encrypted_message = base64.b64decode(encrypted_message)
    if isinstance(private_key, str):
        private_key = private_key.encode()
    _passphrase = sha512(passphrase)

    encrypted_aes_key = encrypted_message[:256]
    encrypted_message = encrypted_message[256:]

    imported_private_key = RSA.import_key(private_key, passphrase=_passphrase)
    cipher_rsa = PKCS1_OAEP.new(imported_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    decrypted_message = aes_decrypt(encrypted_message, aes_key)

    return decrypted_message.decode()


async def encrypt_message_async(message: bytes | str, public_key: bytes | str, passphrase: str) -> str:
    return await asyncio.to_thread(encrypt_message, message, public_key, passphrase)


async def decrypt_message_async(encrypted_message: str | bytes, private_key: bytes | str, passphrase: str) -> str:
    return await asyncio.to_thread(decrypt_message, encrypted_message, private_key, passphrase)


def generate_chars():
    digits = string.digits
    base61_chars = digits + string.ascii_letters + punctuation()
    return base61_chars


def punctuation():
    unwanted_chars = "/\\:*?\"<>|-"
    valid_punctuation = ''.join(c for c in string.punctuation if c not in unwanted_chars)
    return valid_punctuation


def compress_int(num: int):
    if num == 0:
        return '0'

    chars = generate_chars()
    output = ''
    is_negative = num < 0
    num = abs(num)

    while num > 0:
        output = chars[num % len(chars)] + output
        num //= len(chars)

    if is_negative:
        output = '-' + output

    return output


def get_room_id(passphrase: str) -> int:
    passphrase = sha512(passphrase)
    return random.Random(passphrase).randint(-2**128, 2**128)


def room_db(id: int) -> str:
    folder = './rooms/'
    _id = compress_int(id)
    if not os.path.exists(folder):
        os.makedirs(folder)
    return f"{folder}{_id}.db"


class Room():
    def __init__(
                self, id: int | None, passphrase: str | None,
                public_key: bytes | None, private_key: bytes | None
            ) -> None:
        self.id = id
        self.passphrase = passphrase
        self.public_key = public_key
        self.private_key = private_key
        self.load_success = True


class UnknownRoom(Room):
    def __init__(self) -> None:
        super().__init__(None, None, None, None)
        self.load_success = False


async def room_database(db: aiosqlite.Connection):
    sql = await db.cursor()
    await sql.executescript(
        """
        CREATE TABLE IF NOT EXISTS encryption (
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            passphrase_sha512 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            nickname TEXT PRIMARY KEY,
            password_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            message TEXT NOT NULL,
            attachment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            type INTEGER DEFAULT 1,
            FOREIGN KEY (nickname) REFERENCES accounts(nickname)
        );
        CREATE TABLE IF NOT EXISTS online (
            nickname TEXT,
            online_timestamp INTEGER,
            FOREIGN KEY (nickname) REFERENCES accounts(nickname)
        )
        """
    )


async def create_room(passphrase: str | None = None, prefix: str | None = None) -> Room:
    prefix = prefix or ""
    passphrase = passphrase or f"{prefix}{generate_passphrase(9, 3, 8)}"
    passphrase_sha512 = sha512(passphrase)
    id = get_room_id(passphrase)
    keys = generate_rsa_key(passphrase)
    async with aiosqlite.connect(room_db(id)) as db:
        sql = await db.cursor()
        await room_database(db)
        await sql.execute(
            "INSERT INTO encryption (public_key, private_key, passphrase_sha512) VALUES (?, ?, ?)",
            (keys[1], keys[0], passphrase_sha512)
            )
        await db.commit()
        return Room(id, passphrase, keys[1], keys[0])


async def load_room(passphrase: str) -> Room:
    id = get_room_id(passphrase)
    if not os.path.exists(room_db(id)):
        return UnknownRoom()
    passphrase_sha512 = sha512(passphrase)
    async with aiosqlite.connect(room_db(id)) as db:
        sql = await db.cursor()
        await room_database(db)
        encryption = await (await sql.execute(
            "SELECT public_key, private_key FROM encryption WHERE passphrase_sha512 = ?",
            (passphrase_sha512,)
        )).fetchone()
        if encryption is None:
            return UnknownRoom()
        public_key, private_key = encryption[0], encryption[1]
        message = 'Test key 123'
        try:
            encrypted = encrypt_message(message, public_key, passphrase)
            decrypted = decrypt_message(encrypted, private_key, passphrase)
        except TypeError:
            return UnknownRoom()
        if decrypted != message:
            return UnknownRoom()

        return Room(id, passphrase, public_key, private_key)


class User():
    def __init__(self, nickname: str, password_sha256: str | None = None) -> None:
        self.nickname = nickname
        self.password_sha256 = password_sha256

    async def exists(self, db: aiosqlite.Connection) -> bool:
        sql = await db.cursor()
        user = await (await sql.execute(
            "SELECT * FROM accounts WHERE nickname = ?",
            (self.nickname,)
        )).fetchone()
        return (user is not None)

    async def check_password(self, db: aiosqlite.Connection) -> bool:
        sql = await db.cursor()
        user = await (await sql.execute(
            "SELECT * FROM accounts WHERE nickname = ? AND password_sha256 = ?",
            (self.nickname, self.password_sha256)
        )).fetchone()
        return (user is not None)


async def create_user(nickname: str, password: str, db: aiosqlite.Connection, sql: aiosqlite.Cursor | None = None) -> User:
    sql = sql or (await db.cursor())
    password_sha256 = sha256(password)
    await sql.execute(
        "INSERT INTO accounts (nickname, password_sha256) VALUES (?, ?)",
        (nickname, password_sha256)
    )
    return User(nickname, password_sha256)


async def test():
    try:
        room = await create_room()
        passphrase = room.passphrase
        loaded_room = await load_room(passphrase)
        id = loaded_room.id

        print(f"passphrase: {passphrase}")
        print(f"room id: {get_room_id(passphrase)}")
        print(f"room database: {room_db(id)}")

        message = generate_passphrase(5, 1, 5)
        encrypted = encrypt_message(message, room.public_key, passphrase)
        decrypted = decrypt_message(encrypted, loaded_room.private_key, passphrase)
        encryption_test = "Passed" if decrypted == message else "Failed"
        print(f"\nEncryption test: {encryption_test}")

        message = generate_passphrase(100, 1, 5)
        encrypted = encrypt_message(message, room.public_key, passphrase)
        decrypted = decrypt_message(encrypted, loaded_room.private_key, passphrase)
        encryption_test = "Passed" if decrypted == message else "Failed"
        print(f"Encryption test 2: {encryption_test}")

        async with aiosqlite.connect(room_db(id)) as db:
            nickname = generate_random_word(7)
            password = generate_random_word(15)
            user = await create_user(nickname, password, db)
            user_exists = await user.exists(db)
            check_password = await user.check_password(db)

            user2 = user
            user2.password_sha256 = sha256('a')
            check_password2 = await user2.check_password(db)

            users_test = "Passed" if user_exists and check_password and not check_password2 else "Failed"
            print(f"Auth test: {users_test}")

        input("\nPress Enter to exit")
    finally:
        try:
            os.remove(room_db(id))
        except UnboundLocalError:
            pass
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    asyncio.run(test())
