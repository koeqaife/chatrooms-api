# 1.5
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
import os
import string
import aiosqlite
import random
import re
import hashlib
import base64
import asyncio
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import multiprocessing as mp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# mp.set_start_method('spawn')
mp.set_start_method('spawn', force=True)
executor = ProcessPoolExecutor()

encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

key_file = ".secret_key"


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
    _passphrase = sha512(passphrase).encode()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(_passphrase)
    )

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key


def generate_aes_key() -> bytes:
    return os.urandom(32)


def aes_encrypt(message: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ct)


def aes_decrypt(encrypted_message: bytes, key: bytes) -> bytes:
    encrypted_message = base64.b64decode(encrypted_message)
    iv, tag, ct = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def encrypt_message(message: bytes | str, public_key: bytes | str, passphrase: str) -> str:
    if isinstance(message, str):
        message = message.encode()
    if isinstance(public_key, str):
        public_key = public_key.encode()
    # _passphrase = sha512(passphrase).encode()

    aes_key = generate_aes_key()
    encrypted_message = aes_encrypt(message, aes_key)

    imported_public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_aes_key = imported_public_key.encrypt(  # type: ignore
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_aes_key + encrypted_message).decode()


@lru_cache(maxsize=4)
def load_private_key(private_key: bytes, passphrase: bytes):
    return serialization.load_pem_private_key(private_key, password=passphrase, backend=default_backend())


def decrypt_message(encrypted_message: str | bytes, private_key: bytes | str, passphrase: str) -> str:
    if isinstance(encrypted_message, str):
        encrypted_message = base64.b64decode(encrypted_message)
    if isinstance(private_key, str):
        private_key = private_key.encode()
    _passphrase = sha512(passphrase).encode()

    encrypted_aes_key = encrypted_message[:256]
    encrypted_message = encrypted_message[256:]

    imported_private_key = load_private_key(private_key, _passphrase)

    aes_key = imported_private_key.decrypt(  # type: ignore
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_message = aes_decrypt(encrypted_message, aes_key)

    return decrypted_message.decode()


async def encrypt_message_async(message: bytes | str, public_key: bytes | str, passphrase: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, encrypt_message, message, public_key, passphrase)


async def decrypt_message_async(encrypted_message: str | bytes, private_key: bytes | str, passphrase: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, decrypt_message, encrypted_message, private_key, passphrase)


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
            encrypted = await encrypt_message_async(message, public_key, passphrase)
            decrypted = await decrypt_message_async(encrypted, private_key, passphrase)
        except TypeError:
            return UnknownRoom()
        except ValueError:
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
