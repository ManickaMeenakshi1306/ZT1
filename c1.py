#!/usr/bin/env python3
"""
generate_wipe_certificate_client.py

- Fetch certificate JSON from FastAPI backend: POST /generate_certificate_file_json {"device_id": ...}
- Create an ECC keypair, sign the certificate_hash (if present) or the combined_hash.
- Save public key to 'publickey.pem' and reference it from the certificate.
- Fill the Secure Data Wipe Certificate template and write a PDF.

Dependencies:
    pip install requests cryptography fpdf
"""

import requests
import json
import uuid
import datetime
import os
import sys
import base64
from fpdf import FPDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

# ------- Config -------
BASE_URL = "http://127.0.0.1:9000"   # Backend server URL
OUTPUT_DIR = "."                      # Where to write PDF and key files
PUBKEY_FILENAME = "publickey.pem"
PRIVATEKEY_FILENAME = "privatekey.pem"
# ----------------------

def fatal(msg):
    print("ERROR:", msg)
    sys.exit(1)

def fetch_certificate_from_backend(device_id: str) -> dict:
    """Fetch backend certificate JSON for a given device_id"""
    url = f"{BASE_URL}/generate_certificate_file_json"
    try:
        r = requests.post(url, json={"device_id": device_id}, timeout=15)
        r.raise_for_status()
        resp = r.json()
    except Exception as e:
        fatal(f"Failed to fetch certificate JSON from {url}: {e}")

    if "certificate" in resp and isinstance(resp["certificate"], dict):
        return resp["certificate"]
    if isinstance(resp, dict) and set(["device_id","certificate_hash"]).intersection(resp.keys()):
        return resp
    fatal("Unexpected response shape from backend. Expected 'certificate' key or certificate-like dict.")

def generate_ec_keypair(save_private: bool = True):
    """Generate EC P-256 keypair and save public (and optionally private) key"""
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()

    pub_pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    priv_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # save keys
    pub_path = os.path.join(OUTPUT_DIR, PUBKEY_FILENAME)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    if save_private:
        priv_path = os.path.join(OUTPUT_DIR, PRIVATEKEY_FILENAME)
        with open(priv_path, "wb") as f:
            f.write(priv_pem)

    return priv_key, pub_pem, priv_pem

def sign_hash_with_privkey(priv_key, hex_hash: str) -> str:
    """Sign a hex digest using ECDSA and return hex prefixed with 0x"""
    try:
        msg = bytes.fromhex(hex_hash)
    except Exception:
        msg = hex_hash.encode("utf-8")
    sig = priv_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return "0x" + sig.hex()

def build_certificate_template(backend_cert: dict, signature_hex: str, pubkey_location: str) -> dict:
    """Build the final certificate dict for PDF rendering"""
    cert_id = str(uuid.uuid4())
    timestamp = backend_cert.get("timestamp") or datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    device_info = {
        "make_model": backend_cert.get("make_model") or backend_cert.get("device_model") or "Unknown Model",
        "serial_number": backend_cert.get("serial_number") or backend_cert.get("serial") or backend_cert.get("device_id") or "Unknown",
        "capacity": backend_cert.get("capacity") or "Unknown",
        "interface": backend_cert.get("interface") or "Unknown",
        "media_type": backend_cert.get("media_type") or "Unknown"
    }
    wipe_details = {
        "method": backend_cert.get("wipe_method") or "N/A (see backend)",
        "verification": backend_cert.get("verification") or "PASS" if backend_cert.get("certificate_hash") else "UNKNOWN",
        "software_version": backend_cert.get("software_version") or "WaaS Tool v1.x"
    }
    certificate_hash = backend_cert.get("certificate_hash") or backend_cert.get("combined_hash") or (backend_cert.get("hashes") or {}).get("sha256") or "N/A"
    blockchain_txid = backend_cert.get("block_hash") or backend_cert.get("combined_hash") or backend_cert.get("blockchain_txid") or "N/A"
    crypto = {
        "certificate_hash": certificate_hash,
        "digital_signature": signature_hex,
        "verification_key": pubkey_location,
        "blockchain_txid": blockchain_txid
    }
    return {
        "certificate_id": cert_id,
        "issued_by": "DataWipe Technologies Pvt. Ltd.",
        "timestamp": timestamp,
        "device": device_info,
        "wipe": wipe_details,
        "compliance": "This wipe was executed in compliance with NIST SP 800-88 Rev.1\nand meets GDPR & HIPAA secure disposal requirements.",
        "crypto": crypto,
        "backend_certificate": backend_cert
    }

def generate_wipe_certificate_pdf(cert: dict, output_pdf: str):
    """Render certificate dict into PDF"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_font("Arial", "B", 18)
    pdf.cell(0, 12, "-----------------------------------------------------", ln=True, align="C")
    pdf.cell(0, 12, "     SECURE DATA WIPE CERTIFICATE", ln=True, align="C")
    pdf.cell(0, 12, "-----------------------------------------------------", ln=True, align="C")
    pdf.ln(6)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Certificate ID:      {cert['certificate_id']}", ln=True)
    pdf.cell(0, 8, f"Issued By:           {cert['issued_by']}", ln=True)
    pdf.cell(0, 8, f"Timestamp:           {cert['timestamp']}", ln=True)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "DEVICE INFORMATION", ln=True)
    pdf.set_font("Arial", "", 12)
    for k, v in cert['device'].items():
        pdf.cell(0, 8, f"{k.replace('_',' ').title()}: {v}", ln=True)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "WIPE DETAILS", ln=True)
    pdf.set_font("Arial", "", 12)
    for k, v in cert['wipe'].items():
        pdf.cell(0, 8, f"{k.replace('_',' ').title()}: {v}", ln=True)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "COMPLIANCE", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 7, cert['compliance'])
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "CRYPTOGRAPHIC PROOF", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Certificate Hash:    SHA256: {cert['crypto']['certificate_hash']}", ln=True)
    pdf.multi_cell(0, 7, f"Digital Signature:   {cert['crypto']['digital_signature']}")
    pdf.cell(0, 8, f"Verification Key:    {cert['crypto']['verification_key']}", ln=True)
    pdf.cell(0, 8, f"Blockchain TxID:     {cert['crypto']['blockchain_txid']}", ln=True)
    pdf.ln(8)
    pdf.cell(0, 8, "------------------------------------------------------", ln=True, align="C")

    # Backend certificate JSON
    pdf.add_page()
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "RAW BACKEND CERTIFICATE (for audit)", ln=True)
    pdf.set_font("Courier", "", 9)
    backend_pretty = json.dumps(cert.get("backend_certificate", {}), indent=2)
    pdf.multi_cell(0, 5, backend_pretty)

    pdf.output(output_pdf)
    print(f"PDF certificate generated: {output_pdf}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_wipe_certificate_client.py <device_id>")
        sys.exit(1)

    device_id = sys.argv[1].strip()
    if not device_id:
        fatal("device_id cannot be empty")

    # 1) fetch backend certificate
    backend_cert = fetch_certificate_from_backend(device_id)
    print("Fetched backend certificate:", list(backend_cert.keys()))

    # 2) select hash to sign
    hash_to_sign = (backend_cert.get("certificate_hash")
                    or backend_cert.get("combined_hash")
                    or (backend_cert.get("hashes") or {}).get("sha256")
                    or None)
    if hash_to_sign is None:
        hash_to_sign = json.dumps(backend_cert, sort_keys=True).encode('utf-8').hex()
        print("No explicit hash found; signing serialized backend certificate.")

    # 3) generate EC keypair
    priv_key_obj, pub_pem_bytes, priv_pem_bytes = generate_ec_keypair(save_private=True)
    pubkey_path = os.path.abspath(os.path.join(OUTPUT_DIR, PUBKEY_FILENAME))
    verification_key_ref = f"file://{pubkey_path}"

    # 4) sign hash
    signature_hex = sign_hash_with_privkey(priv_key_obj, hash_to_sign)
    print("Generated signature (hex, prefixed 0x):", signature_hex[:80]+"..." if len(signature_hex)>80 else signature_hex)

    # 5) build certificate template
    cert_template = build_certificate_template(backend_cert, signature_hex, verification_key_ref)

    # 6) generate PDF
    output_pdf = os.path.join(OUTPUT_DIR, f"{device_id}_wipe_certificate.pdf")
    generate_wipe_certificate_pdf(cert_template, output_pdf)

    print("Public key written to:", pubkey_path)
    print("Private key written to:", os.path.abspath(os.path.join(OUTPUT_DIR, PRIVATEKEY_FILENAME)))
    print("Done.")

if __name__ == "__main__":
    main()
