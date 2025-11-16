import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def sha256(data):
    """Hash bytes, string, or dict"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def generate_keys(key_dir="keys/"):
    """Generate ECDSA P-384 keys (simulating HSM keygen)"""
    os.makedirs(key_dir, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    
    # Save private key (simulated HSM storage)
    with open(os.path.join(key_dir, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(os.path.join(key_dir, "public_key.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key, public_key

def load_private_key(key_path):
    """Load private key (simulated HSM access)"""
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None, default_backend())

def load_public_key(key_path):
    """Load public key for verification"""
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), default_backend())

def sign(data, private_key):
    """Sign data with ECDSA"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
    
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify(data, signature, public_key):
    """Verify ECDSA signature"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
    
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

def build_merkle_tree(leaves):
    """Build Merkle tree from list of hex hashes, return root"""
    if not leaves:
        return sha256("empty")
    
    # Ensure leaves are bytes
    leaf_bytes = [bytes.fromhex(leaf) if isinstance(leaf, str) else leaf for leaf in leaves]
    
    tree = [leaf_bytes]
    while len(tree[-1]) > 1:
        level = []
        for i in range(0, len(tree[-1]), 2):
            left = tree[-1][i]
            right = tree[-1][i+1] if i+1 < len(tree[-1]) else left
            combined = hashlib.sha256(left + right).digest()
            level.append(combined)
        tree.append(level)
    
    return tree[-1][0].hex()  # Return root as hex string

def merkle_proof(leaf_index, leaves):
    """Generate minimal Merkle proof"""
    if leaf_index >= len(leaves):
        return []
    
    proof = []
    index = leaf_index
    tree = leaves
    
    while len(tree) > 1:
        if index % 2 == 0 and index + 1 < len(tree):
            proof.append(tree[index + 1].hex() if isinstance(tree[index + 1], bytes) else tree[index + 1])
        elif index % 2 == 1:
            proof.append(tree[index - 1].hex() if isinstance(tree[index - 1], bytes) else tree[index - 1])
        
        # Build next level
        next_level = []
        for i in range(0, len(tree), 2):
            left = tree[i]
            right = tree[i+1] if i+1 < len(tree) else left
            combined = hashlib.sha256(
                (left if isinstance(left, bytes) else bytes.fromhex(left)) + 
                (right if isinstance(right, bytes) else bytes.fromhex(right))
            ).digest()
            next_level.append(combined)
        
        tree = next_level
        index //= 2
    
    return proof

def verify_merkle_proof(leaf, proof, root):
    """Verify Merkle proof"""
    current = leaf if isinstance(leaf, bytes) else bytes.fromhex(leaf)
    
    for sibling in proof:
        sibling_bytes = sibling if isinstance(sibling, bytes) else bytes.fromhex(sibling)
        current = hashlib.sha256(current + sibling_bytes).digest()
    
    return current.hex() == (root if isinstance(root, str) else root.hex())