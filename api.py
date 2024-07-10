import json
import time
import aiosqlite
from quart import Quart, jsonify, request
import logging
import asyncio
import core
import functions
from redis import Redis
import traceback

VERSION = 4
db_manager = core.AsyncDatabaseConnectionManager()

core.init_logging(logging.INFO, True, True, other_logs=True)
LOGGER = logging.getLogger("api")
core.warn_if_not_optimized(False)
config = {
    "ip": "0.0.0.0",
    "port": 1111,
    "redis": "localhost",
    "redis_port": 6379,
    "rate_limit": 60
}
try:
    with open("./config.json") as f:
        config.update(json.load(f))
except Exception:
    traceback.print_exc()

session_prefix = core.new_session_prefix()

redis = Redis(host=config["redis"], port=config["redis_port"], db=0)
app = Quart(__name__)


@app.errorhandler(500)
async def handle_500(error):
    traceback.print_exc()
    response = {
        "message": "Internal Server Error",
        "success": False
    }
    return jsonify(response), 500


@app.errorhandler(Exception)
async def handle_exception(error):
    traceback.print_exc()
    response = {
        "message": "Server Error",
        "success": False
    }
    return jsonify(response), 500


async def check_ip_rate_limit(_key: str | None, limit=30, interval=60):
    # return True
    if _key is None:
        return False
    key = f'rate_limit:{_key}'
    current_count = redis.incr(key)
    if current_count == 1:
        redis.expire(key, interval)
    if current_count > limit:
        return False
    return True


@app.before_request
async def before():
    client_ip = request.remote_addr
    if "bypass" in request.headers:
        rate_limit_bypass = request.headers["bypass"]
    else:
        rate_limit_bypass = None
    if not str(functions.secret_key) == rate_limit_bypass:
        if not (await check_ip_rate_limit(client_ip, limit=config["rate_limit"])):
            return {
                "message": 'Rate limit exceeded',
                "success": False,
                "rate_limit": True
            }, 429


room_is_null = json.dumps({
    "message": "room is null",
    "success": False
}), 400
password_or_username_is_null = json.dumps({
    "success": False,
    "message": "password or username is null"
}), 400


@app.route('/create_room', methods=['POST'])
async def create_room():
    new_room = await functions.create_room(prefix=session_prefix+" ")
    return jsonify(
        {
            "key": new_room.passphrase,
            "id": new_room.id,
            "success": True
        }
    )


async def auth(
    room_key: str | None, username: str | None, password: str | None
) -> tuple[tuple | str, tuple[None, None]] | tuple[None, tuple[functions.Room, functions.User]]:
    if room_key is None:
        return tuple(room_is_null), (None, None)

    if password is None or username is None:
        return tuple(password_or_username_is_null), (None, None)

    room = await functions.load_room(room_key)

    if not room.load_success:
        return (json.dumps({
            "success": False,
            "message": "Room doesn't exists"
        }), 400), (None, None)

    user = functions.User(username, functions.sha256(password))
    return None, (room, user)


@app.route('/get_room', methods=['GET'])
async def get_room():
    room_key = request.headers.get('room')
    if room_key is None:
        return room_is_null
    room = await functions.load_room(room_key)
    return jsonify(
        {
            "key": room.passphrase,
            "id": room.id,
            "success": room.load_success
        }
    ), 200 if room.load_success else 400


@app.route('/create_user', methods=['POST'])
async def create_user():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        if (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User already exists"
            }), 400
        await functions.create_user(username, password, db)
        await db.commit()

    return jsonify(
        {
            "success": True
        }
    )


@app.route('/check_user', methods=['GET'])
async def check_user():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        if not (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User doesn't exists"
            }), 400
        if not (await user.check_password(db)):
            return jsonify({
                "success": False,
                "message": "Wrong password"
            }), 403

    return jsonify(
        {
            "success": True
        }
    )


@app.route('/send_message', methods=['POST'])
async def send_message():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    message = data.get("text")
    if message is None or len(str(message).strip()) == 0:
        return jsonify({
            "message": "text cannot be empty",
            "success": False
        }), 400
    try:
        type = int(data.get("type") or 1)
    except Exception:
        type = 1

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        db: aiosqlite.Connection  # type: ignore
        if not (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User doesn't exists"
            }), 400
        if not (await user.check_password(db)):
            return jsonify({
                "success": False,
                "message": "Wrong password"
            }), 403

        encrypted_msg = await functions.encrypt_message_async(message, room.public_key, room.passphrase)
        await db.execute(
            "INSERT INTO messages (nickname, message, type) VALUES (?, ?, ?)",
            (user.nickname, encrypted_msg, type)
        )
        await db.commit()

    return jsonify(
        {
            "success": True
        }
    )


@app.route('/get_last_messages', methods=['GET'])
async def get_last_messages():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    try:
        after = int(data.get("after_message") or 0)
    except Exception:
        after = 0

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        db: aiosqlite.Connection  # type: ignore
        if not (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User doesn't exists"
            }), 400
        if not (await user.check_password(db)):
            return jsonify({
                "success": False,
                "message": "Wrong password"
            }), 403

        _msg_count = await db.execute("SELECT COUNT(*) FROM messages WHERE id > ?", (after,))
        msg_count = min(100, (await _msg_count.fetchone())[0])
        _messages = await db.execute(
            f"""
                SELECT id, nickname, message, created_at, type
                FROM messages
                ORDER BY id
                DESC LIMIT {msg_count}
            """,
        )
        messages_encrypted = list(await _messages.fetchall())
        messages_encrypted.reverse()
        messages = []

        async def decrypt_messages():
            for (id, nickname, message, created_at, type) in messages_encrypted:
                _decrypted = await functions.decrypt_message_async(message, room.private_key, room.passphrase)
                yield (id, nickname, _decrypted, created_at, type)

        try:
            async for (id, nickname, message, created_at, type) in decrypt_messages():
                messages.append({
                    "id": id,
                    "nickname": nickname,
                    "message": message,
                    "created_at": created_at,
                    "type": type
                })
        except ValueError:
            return jsonify({
                "success": False,
                "message": "Couldn't decrypt one of the messages"
            }), 500

    return jsonify({
        "success": True,
        "messages": messages
    })


@app.route('/online', methods=['POST'])
async def online():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        db: aiosqlite.Connection  # type: ignore
        if not (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User doesn't exists"
            }), 400
        if not (await user.check_password(db)):
            return jsonify({
                "success": False,
                "message": "Wrong password"
            }), 403

        _online = await db.execute(
            "SELECT nickname, online_timestamp FROM online WHERE nickname = ?",
            (user.nickname,)
        )
        if (await _online.fetchone()) is not None:
            await db.execute(
                "UPDATE online SET online_timestamp = ? WHERE nickname = ?",
                (time.time(), user.nickname)
            )
        else:
            await db.execute(
                "INSERT INTO online (nickname, online_timestamp) VALUES (?, ?)",
                (user.nickname, time.time())
            )
        await db.commit()

    return jsonify({
        "success": True,
    })


@app.route('/online_list', methods=['GET'])
async def online_list():
    room_key = request.headers.get('room')

    if room_key is None:
        return room_is_null

    data = (await request.get_json()) or {}
    username = data.get("username")
    password = data.get("password")
    _return, room_and_user = await auth(room_key, username, password)
    if _return is not None:
        return _return
    room, user = room_and_user

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        db: aiosqlite.Connection  # type: ignore
        if not (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User doesn't exists"
            }), 400
        if not (await user.check_password(db)):
            return jsonify({
                "success": False,
                "message": "Wrong password"
            }), 403

        _online = await db.execute(
            """
                SELECT nickname, online_timestamp FROM online
                WHERE online_timestamp > (strftime('%s', 'now') - 15)
                LIMIT 101
            """,
        )
        _online_list = await _online.fetchall()
        _online_count = await db.execute(
            """
                SELECT COUNT(*) FROM online
                WHERE online_timestamp > (strftime('%s', 'now') - 15)
            """,
        )
        online_count = (await _online_count.fetchone()) or 0
        online_list = []
        for nickname, online_timestamp in _online_list:
            online_list.append({
                "nickname": nickname,
                "timestamp": online_timestamp
            })

    return jsonify({
        "success": True,
        "hidden": online_count[0] > 100,
        "online": online_list,
        "online_count": online_count[0]
    })


@app.route('/ping', methods=['GET'])
async def ping():
    return "Pong!", 200


@app.route('/info', methods=['GET'])
async def info():
    return jsonify({
        "success": True,
        "max_rate_limit": config["rate_limit"],
        "version": VERSION
    })


async def main_task():
    import ipaddress
    import socket
    LOGGER.info("Initialized")

    ip = ipaddress.IPv4Address(config["ip"])
    host = "0.0.0.0"
    if ip.is_global:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((str(ip), int(config["port"])))
            s.close()
            host = str(ip)
        except OSError as e:
            LOGGER.error(f"OSError occurred: {e}")
            LOGGER.error(f"IP address {ip} is not available")
            LOGGER.error("Trying to bind to a different host")
            host = "0.0.0.0"
    else:
        if host != "0.0.0.0" and host != "127.0.0.1":
            LOGGER.error(f"IP address {ip} is not global")
            LOGGER.error("Trying to bind to a different host")
        host = "0.0.0.0"

    quart_task = asyncio.create_task(
        app.run_task(
            debug=False, port=int(config["port"]), host=host,
            certfile="cert.pem",
            keyfile="key.pem"
        )
    )
    asyncio.create_task(
        db_manager.cleanup_connections()
    )
    await asyncio.gather(quart_task)


if __name__ == '__main__':
    asyncio.run(main_task())
