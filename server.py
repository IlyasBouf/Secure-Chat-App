"""
Secure Chat Application – Python WebSocket Server
===================================================
Features:
  - User registration & login with bcrypt password hashing
  - HMAC-SHA256 token-based session authentication
  - WebSocket relay for encrypted messages (E2E – server never sees plaintext)
  - ECDH public-key relay for key exchange between peers
  - Online user presence broadcasting
  - Group chat creation with encrypted group key sharing
  - File transfer relay (encrypted, up to 5 MB)
  - Single WebSocket per user (fixes duplicate message bug)
"""

import asyncio
import json
import hashlib
import hmac
import secrets
import time
import os
import sys
from pathlib import Path
from http import HTTPStatus

import bcrypt
import websockets
from websockets.http import Headers

# ── Configuration ──────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 3000
TOKEN_SECRET = secrets.token_hex(32)
TOKEN_EXPIRY = 86400  # 24 hours
DATA_DIR = Path(__file__).parent / "data"
USERS_FILE = DATA_DIR / "users.json"
GROUPS_FILE = DATA_DIR / "groups.json"
STATIC_DIR = Path(__file__).parent / "public"
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB base64 payload limit

# ── In-memory state ───────────────────────────────────────────────────────────
# Only ONE active WebSocket per username to prevent duplicate messages
connected_clients: dict[str, object] = {}   # username -> single websocket
user_db: dict = {}        # username -> {"password_hash": ..., "created_at": ...}
groups_db: dict = {}      # group_id -> {"name", "creator", "members": [...]}


# ── Persistence ────────────────────────────────────────────────────────────────
def load_users():
    global user_db
    if USERS_FILE.exists():
        with open(USERS_FILE, "r") as f:
            user_db = json.load(f)


def save_users():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(user_db, f, indent=2)


def load_groups():
    global groups_db
    if GROUPS_FILE.exists():
        with open(GROUPS_FILE, "r") as f:
            groups_db = json.load(f)


def save_groups():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(GROUPS_FILE, "w") as f:
        json.dump(groups_db, f, indent=2)


# ── Token helpers ──────────────────────────────────────────────────────────────
def create_token(username: str) -> str:
    payload = json.dumps({"sub": username, "exp": int(time.time()) + TOKEN_EXPIRY})
    sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def verify_token(token: str) -> str | None:
    try:
        payload_str, sig = token.rsplit("|", 1)
        expected = hmac.new(TOKEN_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(payload_str)
        if payload.get("exp", 0) < time.time():
            return None
        return payload.get("sub")
    except Exception:
        return None


# ── Broadcast helpers ──────────────────────────────────────────────────────────
async def broadcast_user_list():
    """Send the list of currently online users to everyone."""
    online = list(connected_clients.keys())
    message = json.dumps({"type": "user-list", "users": online})
    tasks = []
    for username, ws in connected_clients.items():
        tasks.append(asyncio.create_task(safe_send(ws, message)))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def safe_send(ws, message: str):
    """Send a message, ignoring closed connection errors."""
    try:
        await ws.send(message)
    except Exception:
        pass


async def send_to_user(username: str, data: dict):
    """Send a JSON message to a specific user's single active connection."""
    ws = connected_clients.get(username)
    if ws:
        await safe_send(ws, json.dumps(data))


async def broadcast_to_group(group_id: str, data: dict, exclude: str = None):
    """Relay a message to all online members of a group."""
    group = groups_db.get(group_id)
    if not group:
        return
    tasks = []
    for member in group.get("members", []):
        if member == exclude:
            continue
        ws = connected_clients.get(member)
        if ws:
            tasks.append(asyncio.create_task(safe_send(ws, json.dumps(data))))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


# ── WebSocket handler ──────────────────────────────────────────────────────────
async def chat_handler(websocket):
    """Main WebSocket connection handler."""
    username = None
    try:
        # First message must be authentication
        auth_msg = await asyncio.wait_for(websocket.recv(), timeout=10)
        auth_data = json.loads(auth_msg)

        if auth_data.get("type") != "auth":
            await websocket.send(json.dumps({"type": "error", "message": "First message must be auth"}))
            return

        token = auth_data.get("token", "")
        username = verify_token(token)
        if not username:
            await websocket.send(json.dumps({"type": "auth-error", "message": "Invalid or expired token"}))
            return

        # ── SINGLE CONNECTION PER USER: kick old connection ──────────────────
        old_ws = connected_clients.get(username)
        if old_ws and old_ws is not websocket:
            try:
                await old_ws.send(json.dumps({
                    "type": "kicked",
                    "message": "You connected from another tab. This session was replaced."
                }))
                await old_ws.close()
            except Exception:
                pass

        # Register this as the sole active connection
        connected_clients[username] = websocket

        await websocket.send(json.dumps({
            "type": "auth-success",
            "username": username,
            "groups": [
                {"id": gid, "name": g.get("name"), "members": g.get("members", []), "creator": g.get("creator")}
                for gid, g in groups_db.items()
                if username in g.get("members", [])
            ]
        }))
        await broadcast_user_list()

        # Message loop
        async for raw in websocket:
            try:
                data = json.loads(raw)
                msg_type = data.get("type")

                # ── Encrypted DM ─────────────────────────────────────────────
                if msg_type == "encrypted-message":
                    target = data.get("to")
                    msg_id = data.get("msgId", "")
                    if target and target in connected_clients:
                        await send_to_user(target, {
                            "type": "encrypted-message",
                            "from": username,
                            "payload": data.get("payload"),
                            "iv": data.get("iv"),
                            "timestamp": data.get("timestamp", int(time.time() * 1000)),
                            "msgId": msg_id,
                        })
                        await safe_send(websocket, json.dumps({
                            "type": "message-sent",
                            "to": target,
                            "msgId": msg_id,
                            "timestamp": data.get("timestamp", int(time.time() * 1000)),
                        }))
                    else:
                        await safe_send(websocket, json.dumps({
                            "type": "error",
                            "message": f"User '{target}' is not online"
                        }))

                # ── Key Exchange ─────────────────────────────────────────────
                elif msg_type == "key-exchange":
                    target = data.get("to")
                    if target and target in connected_clients:
                        await send_to_user(target, {
                            "type": "key-exchange",
                            "from": username,
                            "publicKey": data.get("publicKey"),
                        })

                elif msg_type == "key-exchange-response":
                    target = data.get("to")
                    if target and target in connected_clients:
                        await send_to_user(target, {
                            "type": "key-exchange-response",
                            "from": username,
                            "publicKey": data.get("publicKey"),
                        })

                # ── Typing indicator ─────────────────────────────────────────
                elif msg_type == "typing":
                    target = data.get("to")
                    group_id = data.get("groupId")
                    if group_id:
                        await broadcast_to_group(group_id, {
                            "type": "typing",
                            "from": username,
                            "groupId": group_id,
                            "isTyping": data.get("isTyping", False),
                        }, exclude=username)
                    elif target and target in connected_clients:
                        await send_to_user(target, {
                            "type": "typing",
                            "from": username,
                            "isTyping": data.get("isTyping", False),
                        })

                # ── Group: Create ────────────────────────────────────────────
                elif msg_type == "create-group":
                    group_name = data.get("name", "").strip()
                    members = data.get("members", [])  # list of usernames

                    if not group_name:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Group name cannot be empty"
                        }))
                        continue

                    if len(group_name) > 40:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Group name too long (max 40 chars)"
                        }))
                        continue

                    # Ensure creator is in members
                    all_members = list(set([username] + [m for m in members if m in user_db]))
                    group_id = secrets.token_hex(8)

                    groups_db[group_id] = {
                        "name": group_name,
                        "creator": username,
                        "members": all_members,
                        "created_at": int(time.time()),
                    }
                    save_groups()

                    group_info = {
                        "id": group_id,
                        "name": group_name,
                        "members": all_members,
                        "creator": username,
                    }

                    # Notify all members (including creator)
                    for member in all_members:
                        await send_to_user(member, {
                            "type": "group-created",
                            "group": group_info,
                        })

                # ── Group: Key Share ─────────────────────────────────────────
                elif msg_type == "group-key-share":
                    # Creator encrypts group AES key with each member's shared key
                    # and sends it. We just relay it to the target.
                    target = data.get("to")
                    group_id = data.get("groupId")
                    if target and group_id and groups_db.get(group_id):
                        if username in groups_db[group_id].get("members", []):
                            await send_to_user(target, {
                                "type": "group-key-share",
                                "from": username,
                                "groupId": group_id,
                                "encryptedKey": data.get("encryptedKey"),
                                "iv": data.get("iv"),
                            })

                # ── Group: Key Request ─────────────────────────────────────
                elif msg_type == "group-key-request":
                    group_id = data.get("groupId")
                    group = groups_db.get(group_id)

                    if not group:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Group not found"
                        }))
                        continue

                    if username not in group.get("members", []):
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Not a member of this group"
                        }))
                        continue

                    creator = group.get("creator")
                    if creator and creator in connected_clients:
                        await send_to_user(creator, {
                            "type": "group-key-request",
                            "from": username,
                            "groupId": group_id,
                        })
                    else:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Group creator is offline"
                        }))

                # ── Group: Message ───────────────────────────────────────────
                elif msg_type == "group-message":
                    group_id = data.get("groupId")
                    msg_id = data.get("msgId", "")
                    group = groups_db.get(group_id)

                    if not group:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Group not found"
                        }))
                        continue

                    if username not in group.get("members", []):
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Not a member of this group"
                        }))
                        continue

                    relay = {
                        "type": "group-message",
                        "from": username,
                        "groupId": group_id,
                        "payload": data.get("payload"),
                        "iv": data.get("iv"),
                        "timestamp": data.get("timestamp", int(time.time() * 1000)),
                        "msgId": msg_id,
                    }
                    # Broadcast to all members except sender
                    await broadcast_to_group(group_id, relay, exclude=username)

                # ── Group: Add Member ────────────────────────────────────────
                elif msg_type == "group-add-member":
                    group_id = data.get("groupId")
                    new_member = data.get("username")
                    group = groups_db.get(group_id)

                    if not group or group.get("creator") != username:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "Only the group creator can add members"
                        }))
                        continue

                    if new_member not in user_db:
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": f"User '{new_member}' does not exist"
                        }))
                        continue

                    if new_member not in group["members"]:
                        group["members"].append(new_member)
                        save_groups()

                    group_info = {
                        "id": group_id,
                        "name": group["name"],
                        "members": group["members"],
                        "creator": group["creator"],
                    }
                    # Notify new member and all existing members
                    for member in group["members"]:
                        await send_to_user(member, {
                            "type": "group-member-added",
                            "group": group_info,
                            "newMember": new_member,
                        })

                # ── File Transfer (DM) ───────────────────────────────────────
                elif msg_type == "file-message":
                    target = data.get("to")
                    group_id = data.get("groupId")
                    msg_id = data.get("msgId", "")

                    # Size check on the base64 payload
                    payload = data.get("payload", "")
                    if len(payload) > MAX_FILE_SIZE_BYTES * 1.4:  # base64 overhead ~1.37x
                        await safe_send(websocket, json.dumps({
                            "type": "error", "message": "File too large (max 5 MB)"
                        }))
                        continue

                    file_relay = {
                        "type": "file-message",
                        "from": username,
                        "payload": payload,
                        "iv": data.get("iv"),
                        "fileName": data.get("fileName", "file"),
                        "fileType": data.get("fileType", "application/octet-stream"),
                        "fileSize": data.get("fileSize", 0),
                        "timestamp": data.get("timestamp", int(time.time() * 1000)),
                        "msgId": msg_id,
                    }

                    if group_id:
                        group = groups_db.get(group_id)
                        if group and username in group.get("members", []):
                            file_relay["groupId"] = group_id
                            await broadcast_to_group(group_id, file_relay, exclude=username)
                    elif target and target in connected_clients:
                        file_relay["to"] = target
                        await send_to_user(target, file_relay)
                        await safe_send(websocket, json.dumps({
                            "type": "message-sent",
                            "to": target,
                            "msgId": msg_id,
                        }))

            except json.JSONDecodeError:
                await safe_send(websocket, json.dumps({"type": "error", "message": "Invalid JSON"}))

    except asyncio.TimeoutError:
        pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username and connected_clients.get(username) is websocket:
            del connected_clients[username]
            await broadcast_user_list()


# ── Simple HTTP server for REST API + static files ─────────────────────────────
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import urllib.parse


class ChatHTTPHandler(SimpleHTTPRequestHandler):
    """Serves static files from /public and handles auth API endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_POST(self):
        if self.path == "/api/register":
            self._handle_register()
        elif self.path == "/api/login":
            self._handle_login()
        else:
            self.send_error(404)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        return json.loads(body)

    def _send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_register(self):
        try:
            data = self._read_json_body()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                self._send_json(400, {"error": "Username and password are required"})
                return

            if len(username) < 3 or len(username) > 20:
                self._send_json(400, {"error": "Username must be 3-20 characters"})
                return

            if len(password) < 6:
                self._send_json(400, {"error": "Password must be at least 6 characters"})
                return

            if not username.isalnum():
                self._send_json(400, {"error": "Username must be alphanumeric"})
                return

            if username in user_db:
                self._send_json(409, {"error": "Username already taken"})
                return

            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
            user_db[username] = {
                "password_hash": password_hash,
                "created_at": int(time.time()),
            }
            save_users()

            token = create_token(username)
            self._send_json(201, {"token": token, "username": username})

        except Exception as e:
            self._send_json(500, {"error": "Internal server error"})

    def _handle_login(self):
        try:
            data = self._read_json_body()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                self._send_json(400, {"error": "Username and password are required"})
                return

            user = user_db.get(username)
            if not user:
                self._send_json(401, {"error": "Invalid credentials"})
                return

            if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                self._send_json(401, {"error": "Invalid credentials"})
                return

            token = create_token(username)
            self._send_json(200, {"token": token, "username": username})

        except Exception as e:
            self._send_json(500, {"error": "Internal server error"})

    def log_message(self, format, *args):
        """Suppress default logging to keep console clean."""
        pass


def start_http_server():
    """Run the HTTP server in a background thread."""
    server = HTTPServer((HOST, PORT), ChatHTTPHandler)
    print(f"  HTTP server:      http://localhost:{PORT}")
    server.serve_forever()


# ── Main ───────────────────────────────────────────────────────────────────────
async def main():
    load_users()
    load_groups()

    print()
    print("  +----------------------------------------------+")
    print("  |     Secure Chat Server Running               |")
    print("  +----------------------------------------------+")
    print(f"  |  Registered users:  {len(user_db):<24}|")
    print(f"  |  Groups loaded:     {len(groups_db):<24}|")
    print("  +----------------------------------------------+")
    print()

    # Start HTTP server in background thread
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    # Start WebSocket server on a different port
    ws_port = PORT + 1
    async with websockets.serve(chat_handler, HOST, ws_port):
        print(f"  WebSocket server:  ws://localhost:{ws_port}")
        print()
        print("  Ready for connections. Press Ctrl+C to stop.")
        print()
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  Server stopped.")
