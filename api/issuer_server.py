# api/issuer_server.py
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json
from pymongo import MongoClient

app = Flask(__name__)

# --- MongoDB Initialization ---
MONGO_URI = os.getenv("MONGO_DB_URI")
client = None
db = None

if MONGO_URI:
    try:
        client = MongoClient(MONGO_URI)
        db = client.OneNationOneCard # Database name
        # Check if the dummy user exists, if not, create it with all new fields.
        if db.users.count_documents({'_id': '123456789012'}) == 0:
            print("Dummy user not found, creating one...")
            db.users.insert_one({
                "_id": "123456789012", # This is the Aadhaar number (Primary Key)
                "name": "Prateek A (Dummy)",
                "sex": "Male",
                "dob": "1998-05-01",
                "voter_id": "ABC1234567",
                "pan": "ABCDE1234F",
                "dl": "KA0120200012345",
                "photo_hash": "sha256:abcdef1234567890" # Keeping this for the original flow
            })
            print("Dummy user created.")
    except Exception as e:
        print(f"ERROR: Could not connect to MongoDB. {e}")
        db = None
else:
    print("WARNING: MONGO_DB_URI not found. Database features will be disabled.")
# -----------------------------

basedir = os.path.abspath(os.path.dirname(__file__))
PRIVATE_KEY_FILE = os.path.join(basedir, '..', 'issuer_priv.pem')
PUBLIC_KEY_FILE = os.path.join(basedir, '..', 'issuer_pub.pem')
ISSUER_ID = "ISSUER01"

with open(PRIVATE_KEY_FILE, "rb") as f:
    issuer_priv = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_FILE, "rb") as f:
    issuer_pub_pem = f.read()

@app.route("/api/fetch_user", methods=["POST"])
def fetch_user():
    if not db:
        return jsonify({"error": "Database not configured on server"}), 500
    
    req = request.json or {}
    aadhaar = req.get("aadhaar")
    if not aadhaar:
        return jsonify({"error": "Aadhaar number missing"}), 400
    
    try:
        user_doc = db.users.find_one({'_id': aadhaar})
        if user_doc:
            return jsonify(user_doc), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def sign_message(priv_key, message_bytes):
    return priv_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))

def derive_key_from_pin(pin: str, salt: bytes, iterations=200_000):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(pin.encode("utf-8"))

@app.route("/api/issue_credential", methods=["POST"])
def issue_credential():
    req = request.json or {}
    # Get all the new fields from the request
    pin = req.get("pin")
    expiry = req.get("expiry")
    
    # The credential data is now the entire request body minus the PIN and expiry
    cred = req.copy()
    cred.pop("pin", None)
    cred.pop("expiry", None)
    cred["i"] = ISSUER_ID # Add the issuer ID

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
        "v": "1",
        "i": ISSUER_ID,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ct": base64.b64encode(ct).decode("utf-8"),
        "sig": sig_b64
    }
    return jsonify({"tag_blob": blob, "issuer_pub_pem": issuer_pub_pem.decode("utf-8")})