# api/issuer_server.py
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

app = Flask(__name__)

# --- MongoDB Initialization ---
MONGO_URI = os.getenv("MONGO_DB_URI")
db = None

if not MONGO_URI:
    print("FATAL_ERROR: MONGO_DB_URI environment variable not found.")
else:
    try:
        print("Attempting to connect to MongoDB...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ismaster')
        print("MongoDB connection successful.")
        db = client.OneNationOneCard

        if db.users.count_documents({'_id': '123456789012'}) == 0:
            print("Dummy user not found, creating one...")
            db.users.insert_one({
                "_id": "123456789012",
                "name": "Prateek A (Dummy)", "sex": "Male", "dob": "1998-05-01",
                "voter_id": "ABC1234567", "pan": "ABCDE1234F", "dl": "KA0120200012345",
                "photo_hash": "sha256:abcdef1234567890"
            })
            print("Dummy user created.")
    except ConnectionFailure as e:
        print(f"FATAL_ERROR: MongoDB connection failed. Could not connect to server: {e}")
        db = None
    except Exception as e:
        print(f"FATAL_ERROR: An unexpected error occurred during DB initialization: {e}")
        db = None
# -----------------------------

basedir = os.path.abspath(os.path.dirname(__file__))
PRIVATE_KEY_FILE = os.path.join(basedir, '..', 'issuer_priv.pem')
PUBLIC_KEY_FILE = os.path.join(basedir, '..', 'issuer_pub.pem')
ISSUER_ID = "ISSUER01"

try:
    with open(PRIVATE_KEY_FILE, "rb") as f:
        issuer_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        issuer_pub_pem = f.read()
except FileNotFoundError as e:
    print(f"FATAL_ERROR: Could not find key files: {e}")
    issuer_priv = None
    issuer_pub_pem = None


@app.route("/api/fetch_user", methods=["POST"])
def fetch_user():
    # --- START OF FIX ---
    # The error log told us to use 'is not None' instead of 'if not db'.
    if db is None:
    # --- END OF FIX ---
        return jsonify({"error": "Database connection failed on the server. Check logs."}), 500
    
    req = request.json or {}
    aadhaar = req.get("aadhaar")
    if not aadhaar:
        return jsonify({"error": "Aadhaar number missing"}), 400
    
    try:
        user_doc = db.users.find_one({'_id': aadhaar})
        if user_doc:
            response_data = {
                "name": user_doc.get("name"), "sex": user_doc.get("sex"), "dob": user_doc.get("dob"),
                "voter_id": user_doc.get("voter_id"), "pan": user_doc.get("pan"), "dl": user_doc.get("dl"),
                "photo_hash": user_doc.get("photo_hash")
            }
            return jsonify(response_data), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"ERROR in fetch_user: {e}")
        return jsonify({"error": "An error occurred while fetching user data."}), 500

def sign_message(priv_key, message_bytes):
    if not priv_key: return None
    return priv_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))

def derive_key_from_pin(pin: str, salt: bytes, iterations=200_000):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(pin.encode("utf-8"))

@app.route("/api/issue_credential", methods=["POST"])
def issue_credential():
    if issuer_priv is None or issuer_pub_pem is None:
        return jsonify({"error": "Server is missing key files. Check logs."}), 500

    req = request.json or {}
    pin = req.get("pin")
    expiry = req.get("expiry")
    
    cred = req.copy()
    cred.pop("pin", None)
    cred.pop("expiry", None)
    cred["i"] = ISSUER_ID

    if not all(k in cred for k in ["name", "dob", "sex", "voter_id", "pan", "dl"]) or not pin:
        return jsonify({"error":"missing fields"}), 400

    if expiry:
        cred["exp"] = expiry
        
    cred_bytes = json.dumps(cred, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = sign_message(issuer_priv, cred_bytes)
    sig_b64 = base64.b64encode(sig).decode("utf-8")
    salt = os.urandom(16)
    key = derive_key_from_pin(pin, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, cred_bytes, associated_data=None)

    blob = {
        "v": "1", "i": ISSUER_ID,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ct": base64.b64encode(ct).decode("utf-8"),
        "sig": sig_b64
    }
    return jsonify({"tag_blob": blob, "issuer_pub_pem": issuer_pub_pem.decode("utf-8")})