# server.py
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import hashlib, json, datetime, base64, os
from typing import List, Dict
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

# ---------------- Block & Merkle Tree ----------------
class Block:
    def __init__(self, index:int, timestamp:str, data:List[Dict], previous_hash:str, merkle_root:str="", nonce:int=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.nonce = nonce
        self.hash = self.compute_hash()
    
    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash
        }

class MerkleTree:
    @staticmethod
    def _leaf_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def _node_hash(left: str, right: str) -> str:
        return hashlib.sha256(bytes.fromhex(left)+bytes.fromhex(right)).hexdigest()
    
    @classmethod
    def root(cls, leaves: List[bytes]) -> str:
        if not leaves:
            return hashlib.sha256(b"").hexdigest()
        nodes = [cls._leaf_hash(l) for l in leaves]
        while len(nodes) > 1:
            if len(nodes) % 2:
                nodes.append(nodes[-1])
            nodes = [cls._node_hash(nodes[i], nodes[i+1]) for i in range(0, len(nodes), 2)]
        return nodes[0]

# ---------------- Blockchain ----------------
LEDGER_FILE = "ledger_pow.json"
class PermissionedBlockchain:
    def __init__(self, difficulty=3, ledger_file=LEDGER_FILE):
        self.chain: List[Block] = []
        self.pending_records: List[Dict] = []
        self.ledger_file = ledger_file
        self.difficulty = difficulty
        self.load_ledger()

    def create_genesis_block(self):
        genesis_block = Block(0, str(datetime.datetime.utcnow()), [], "0", merkle_root="", nonce=0)
        self.chain.append(genesis_block)
        self.save_ledger()

    def add_record(self, record: dict):
        self.pending_records.append(record)
        return len(self.pending_records)

    def save_ledger(self):
        with open(self.ledger_file, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)
    
    def load_ledger(self):
        if os.path.exists(self.ledger_file):
            with open(self.ledger_file, "r") as f:
                blocks = json.load(f)
                self.chain = [Block(b["index"], b["timestamp"], b["data"], b["previous_hash"], b.get("merkle_root",""), b.get("nonce",0)) for b in blocks]
        else:
            self.create_genesis_block()
    
    def last_block(self) -> Block:
        return self.chain[-1]

# ---------------- Digital Signature Helpers ----------------
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
    pub_pem = public_key.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

def sign_data(priv_pem: bytes, cert_bytes: bytes) -> str:
    """
    Sign the SHA-256 hex digest (as bytes) of cert_bytes.
    Returns base64-encoded signature string.
    """
    priv_key = load_pem_private_key(priv_pem, password=None)
    cert_hash = hashlib.sha256(cert_bytes).hexdigest().encode()  # hex digest, then encode to bytes
    sig = priv_key.sign(cert_hash, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def verify_signature(pub_pem: bytes, data: bytes, sig_b64: str) -> bool:
    try:
        pub_key = load_pem_public_key(pub_pem)
        sig = base64.b64decode(sig_b64)
        pub_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# ---------------- Block Proposal, PoW & Finalization ----------------
def propose_block(blockchain: PermissionedBlockchain):
    if not blockchain.pending_records:
        raise ValueError("No pending records")
    leaves = [json.dumps(r, sort_keys=True).encode() for r in blockchain.pending_records]
    merkle_root = MerkleTree.root(leaves)
    header = {
        "index": len(blockchain.chain),
        "timestamp": str(datetime.datetime.utcnow()),
        "merkle_root": merkle_root,
        "previous_hash": blockchain.last_block().hash
    }
    records_snapshot = blockchain.pending_records.copy()
    return header, records_snapshot

def mine_block(blockchain: PermissionedBlockchain, header: dict, records: list):
    nonce = 0
    prefix = "0"*blockchain.difficulty
    while True:
        block_candidate = Block(header["index"], header["timestamp"], records, header["previous_hash"], header["merkle_root"], nonce)
        if block_candidate.hash.startswith(prefix):
            return block_candidate
        nonce += 1

def finalize_block(blockchain: PermissionedBlockchain, block: Block):
    blockchain.chain.append(block)
    for r in block.data:
        if r in blockchain.pending_records:
            blockchain.pending_records.remove(r)
    blockchain.save_ledger()
    return block

# ---------------- Device Wipe Smart Contract ----------------
class DeviceWipeContract:
    def __init__(self, blockchain: PermissionedBlockchain):
        self.blockchain = blockchain
        self.device_keys: Dict[str, str] = {}  # device_id -> public_key_pem

    def register_device(self, device_id: str, public_key_pem: str):
        self.device_keys[device_id] = public_key_pem

    def submit_wipe(self, device_id: str, cert_hash: str, signature: str, timestamp: str):
        if device_id not in self.device_keys:
            raise ValueError("Device not registered")
        
        ts = datetime.datetime.fromisoformat(timestamp)
        now = datetime.datetime.utcnow()
        if ts > now or (now - ts).total_seconds() > 300:
            raise ValueError("Invalid timestamp")

        pub_pem = self.device_keys[device_id]
        if not verify_signature(pub_pem.encode(), cert_hash.encode(), signature):
            raise ValueError("Invalid signature")
        
        record = {
            "device_id": device_id,
            "certificate_hash": cert_hash,
            "timestamp": timestamp,
            "signature": signature
        }
        self.blockchain.add_record(record)
        return record

# ---------------- Certificate Helpers ----------------
def compute_hashes(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest()
    }

def generate_combined_hash(data: bytes) -> str:
    h1 = hashlib.sha256(data).digest()
    h2 = hashlib.sha512(h1).digest()
    h3 = hashlib.sha512(h2).digest()
    final_hash = hashlib.blake2b(h3).hexdigest()
    return final_hash

def generate_certificate(record: dict, block: Block):
    cert = {
        "device_id": record["device_id"],
        "timestamp": record["timestamp"],
        "certificate_hash": record["certificate_hash"],
        "block_index": block.index,
        "block_hash": block.hash,
        "merkle_root": block.merkle_root,
        "hashes": record.get("hashes", {}),
        "combined_hash": record.get("combined_hash", "")
    }
    filename = f"{record['device_id']}_certificate.json"
    with open(filename, "w") as f:
        json.dump(cert, f, indent=2)
    return cert, filename

def verify_certificate(cert: dict, blockchain: PermissionedBlockchain) -> bool:
    block_index = cert.get("block_index")
    if block_index is None or block_index >= len(blockchain.chain):
        return False
    block = blockchain.chain[block_index]
    if block.hash != cert.get("block_hash"):
        return False
    found = any(
        rec.get("certificate_hash") == cert.get("certificate_hash") and
        rec.get("device_id") == cert.get("device_id")
        for rec in block.data
    )
    if not found:
        return False
    if "merkle_root" in cert and cert["merkle_root"] != block.merkle_root:
        return False
    return True

# ---------------- FastAPI ----------------
app = FastAPI(title="ZeroTrace Device Self-Signing Blockchain")
bc = PermissionedBlockchain()
contract = DeviceWipeContract(bc)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------------- API Endpoints ----------------
@app.post("/generate_keys")
def api_generate_keys():
    priv, pub = generate_keys()
    return {"private_key": priv.decode(), "public_key": pub.decode()}

@app.post("/register_device")
def api_register_device(payload: dict = Body(...)):
    device_id = payload.get("device_id")
    public_key = payload.get("public_key")
    if not device_id or not public_key:
        raise HTTPException(400, "Missing fields")
    try:
        contract.register_device(device_id, public_key)
        return {"message": f"Device {device_id} registered."}
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.post("/submit_certificate_json")
def api_submit_certificate_json(payload: dict = Body(...)):
    device_id = payload.get("device_id")
    cert_bytes_b64 = payload.get("cert_bytes_b64")
    signature_b64 = payload.get("signature_b64")

    if not all([device_id, cert_bytes_b64, signature_b64]):
        raise HTTPException(400, "Missing fields")

    cert_bytes = base64.b64decode(cert_bytes_b64)
    hashes = compute_hashes(cert_bytes)
    combined_hash = generate_combined_hash(cert_bytes)
    cert_hash = hashes["sha256"]
    cert_data = json.loads(cert_bytes.decode())
    timestamp = cert_data.get("timestamp")

    try:
        # Submit wipe
        rec = contract.submit_wipe(device_id, cert_hash, signature_b64, timestamp)
        rec["hashes"] = hashes
        rec["combined_hash"] = combined_hash

        # Auto-mine block
        header, records = propose_block(bc)
        mined_block = mine_block(bc, header, records)
        finalized_block = finalize_block(bc, mined_block)

        # Generate certificate file
        cert, filename = generate_certificate(rec, finalized_block)

        return {
            "message": "Wipe certificate submitted and finalized",
            "record": rec,
            "block": finalized_block.to_dict(),
            "certificate": cert,
            "file": filename
        }

    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/download_certificate/{device_id}")
def download_certificate(device_id: str):
    filename = f"{device_id}_certificate.json"
    if not os.path.exists(filename):
        raise HTTPException(404, "Certificate not found")
    return FileResponse(filename, media_type="application/json", filename=filename)

@app.get("/chain")
def api_get_chain():
    return {"length": len(bc.chain), "chain": [b.to_dict() for b in bc.chain]}
