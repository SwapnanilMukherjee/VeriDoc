import os
from utils import sha256, load_private_key, sign

class HSM_Simulator:
    """Simulates TPM/HSM: stores private key and chain state securely"""
    
    def __init__(self, key_dir="keys/"):
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)
        
        # Load or generate keys (simulate HSM key generation)
        private_key_path = os.path.join(key_dir, "private_key.pem")
        if not os.path.exists(private_key_path):
            from utils import generate_keys
            generate_keys(key_dir)
        
        self.private_key = load_private_key(private_key_path)
        self.public_key_path = os.path.join(key_dir, "public_key.pem")
        
        # HSM-protected state: latest event hash (chain head)
        self.latest_event_hash = sha256("genesis")
    
    def chain_and_sign(self, event):
        """
        Simulate HSM atomic operation:
        1. Updates chain hash
        2. Signs event
        Returns (new_chain_hash, signature)
        """
        # Chain the event: Hash_N = SHA256( SHA256(Event) + Hash_N-1 )
        event_hash = sha256(event)
        event_hash_bytes = bytes.fromhex(event_hash)
        prev_hash_bytes = bytes.fromhex(self.latest_event_hash)
        
        new_chain_hash = sha256(event_hash_bytes + prev_hash_bytes)
        
        # Update HSM state (atomically, in real hardware)
        self.latest_event_hash = new_chain_hash
        
        # Sign the event data (not the chain hash)
        signature = sign(event, self.private_key)
        
        return new_chain_hash, signature
    
    def get_latest_hash(self):
        """Get current chain head"""
        return self.latest_event_hash