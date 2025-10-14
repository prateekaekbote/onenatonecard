# issuer_server.py
from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json

app = Flask(__name__, template_folder="templates")

ISSUER_ID = "ISSUER01"
PRIVATE_KEY_FILE = "issuer_priv.pem"
PUBLIC_KEY_FILE = "issuer_pub.pem"

# generate keys if not present (demo only)
if not os.path.exists(PRIVATE_KEY_FILE):
    priv = ec.generate_private_key(ec.SECP256R1())
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    pub = priv.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

with open(PRIVATE_KEY_FILE, "rb") as f:
    issuer_priv = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_FILE, "rb") as f:
    issuer_pub_pem = f.read()

def sign_message(priv_key, message_bytes):
    # ECDSA with SHA256 -> DER signature
    return priv_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))

def derive_key_from_pin(pin: str, salt: bytes, iterations=200_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(pin.encode("utf-8"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/issue_credential", methods=["POST"])
def issue_credential():
    """
    Expected JSON:
    { "name": "...", "dob":"YYYY-MM-DD", "photo_hash":"sha256:...", "pin":"1234", "expiry":"YYYY-MM-DD" }
    Returns: { "tag_blob": {...}, "issuer_pub_pem": "-----BEGIN PUBLIC KEY-----..." }
    """
    req = request.json or {}
    name = req.get("name")
    dob = req.get("dob")
    phash = req.get("photo_hash")
    pin = req.get("pin")
    expiry = req.get("expiry")

    if not (name and dob and phash and pin):
        return jsonify({"error":"missing fields"}), 400

    cred = {"i": ISSUER_ID, "n": name, "dob": dob, "phash": phash}
    if expiry:
        cred["exp"] = expiry
    cred_bytes = json.dumps(cred, separators=(",", ":"), sort_keys=True).encode("utf-8")

    sig = sign_message(issuer_priv, cred_bytes)  # DER sig
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

if __name__ == "__main__":
    # for local testing only. in prod, run behind HTTPS.
    app.run(host="0.0.0.0", port=5000, debug=True)
