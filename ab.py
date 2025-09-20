# device.py
import requests, json, base64
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

SERVER_URL = "http://127.0.0.1:8081"

# ---------------- Step 1: Generate keys (one-time) ----------------
priv_key = ec.generate_private_key(ec.SECP256R1())
pub_key = priv_key.public_key()

priv_pem = priv_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)
pub_pem = pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("device_private.pem", "wb") as f:
    f.write(priv_pem)
with open("device_public.pem", "wb") as f:
    f.write(pub_pem)

device_id = "device123"

# ---------------- Step 2: Register device ----------------
resp = requests.post(f"{SERVER_URL}/register_device", json={
    "device_id": device_id,
    "public_key": pub_pem.decode()
})
print("Register device:", resp.json())

# ---------------- Step 3: Submit wipe certificate ----------------
cert_data = {
    "device_id": device_id,
    "timestamp": datetime.utcnow().isoformat()
}
cert_bytes = json.dumps(cert_data).encode()

with open("device_private.pem", "rb") as f:
    priv_pem = f.read()
priv_key = serialization.load_pem_private_key(priv_pem, password=None)

# Fix: Sign the SHA-256 hex digest (as bytes) of cert_bytes
cert_hash = hashlib.sha256(cert_bytes).hexdigest().encode()
signature = priv_key.sign(cert_hash, ec.ECDSA(hashes.SHA256()))

cert_bytes_b64 = base64.b64encode(cert_bytes).decode()
signature_b64 = base64.b64encode(signature).decode()

resp = requests.post(f"{SERVER_URL}/submit_certificate_json", json={
    "device_id": device_id,
    "cert_bytes_b64": cert_bytes_b64,
    "signature_b64": signature_b64
})
result = resp.json()
print("Submit wipe result:", json.dumps(result, indent=2))

# ---------------- Step 4: Download certificate JSON ----------------
download_resp = requests.get(f"{SERVER_URL}/download_certificate/{device_id}")
with open("my_wipe_certificate.json", "wb") as f:
    f.write(download_resp.content)
print("Certificate downloaded as my_wipe_certificate.json")
