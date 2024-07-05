from quart import Quart, jsonify, request
import logging
import asyncio
import core
import functions
from redis import Redis

db_manager = core.AsyncDatabaseConnectionManager()
redis = Redis(host='localhost', port=6379, db=0)

core.init_logging(logging.INFO, True, True, other_logs=True)
LOGGER = logging.getLogger("api")
core.warn_if_not_optimized(False)
config = {
    "ip": "0.0.0.0",
    "port": 1111
}
session_prefix = core.new_session_prefix()

app = Quart(__name__)


async def check_ip_rate_limit(_key: str | None, limit=30, interval=60):
    if _key is None:
        return False
    key = f'rate_limit:{_key}'
    current_count = redis.incr(key)
    if current_count > limit:
        return False
    redis.expire(key, interval)
    return True


@app.before_request
async def before():
    client_ip = request.remote_addr
    if not (await check_ip_rate_limit(client_ip, limit=45)):
        return {
            "message": 'Rate limit exceeded',
            "success": False
        }, 429
    if not (await check_ip_rate_limit(f"{client_ip}_short", limit=3, interval=5)):
        return {
            "message": 'Rate limit exceeded',
            "success": False
        }, 429


@app.route('/create_room', methods=['POST'])
async def create_room():
    new_room = await functions.create_room(prefix=session_prefix+" ")
    return jsonify(
        {
            "key": new_room.passphrase,
            "id": new_room.id
        }
    )


@app.route('/get_room', methods=['GET'])
async def get_room():
    room_key = request.headers.get('room')
    room = await functions.load_room(room_key)
    return jsonify(
        {
            "key": room.passphrase,
            "id": room.id,
            "success": room.load_success
        }
    ), 200 if room.load_success else 400


@app.route('/create_user', methods=['GET'])
async def create_user():
    room_key = request.headers.get('room')
    data = await request.get_json()
    username = data["username"]
    password = data["password"]
    room = await functions.load_room(room_key)
    user = functions.User(username, functions.sha256(password))

    if not room.load_success:
        return jsonify({
            "success": False,
            "message": "Room doesn't exists"
        }), 400

    async with db_manager.connection_context(functions.room_db(room.id)) as db:
        if (await user.exists(db)):
            return jsonify({
                "success": False,
                "message": "User already exists"
            }), 400
        await functions.create_user(username, password, db)

    return jsonify(
        {
            "key": room.passphrase,
            "id": room.id,
            "success": room.load_success
        }
    )


@app.route('/ping', methods=['GET'])
async def ping():
    return "Pong!", 200


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
