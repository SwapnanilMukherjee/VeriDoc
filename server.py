import os
import time
import json
from utils import sha256, build_merkle_tree, sign
from hsm_sim import HSM_Simulator

class PublicRecordsServer:
    def __init__(self, base_dir="."):
        self.base_dir = base_dir
        self.uploads_dir = os.path.join(base_dir, "uploads")
        self.witness_dir = os.path.join(base_dir, "witness_logs")
        
        # Create directories
        for d in [self.uploads_dir, self.witness_dir]:
            os.makedirs(d, exist_ok=True)
        
        # Initialize witnesses
        for i in range(1, 4):
            witness_file = os.path.join(self.witness_dir, f"witness{i}.txt")
            if not os.path.exists(witness_file):
                open(witness_file, 'w').close()
        
        # Initialize components
        self.hsm = HSM_Simulator(os.path.join(base_dir, "keys"))
        self.events = []  # List of (event, chain_hash, signature)
        self.batch_number = 0
        self.public_key_path = os.path.join(base_dir, "keys", "public_key.pem")
    
    def upload(self, file_path):
        """Simulate file upload, return SUR"""
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        file_hash = sha256(file_content)
        file_store_path = os.path.join(self.uploads_dir, file_hash)
        with open(file_store_path, 'wb') as f:
            f.write(file_content)
        
        event = {
            "action": "upload",
            "file_hash": file_hash,
            "timestamp": time.time(),
            "filename": os.path.basename(file_path)
        }
        
        chain_hash, signature = self.hsm.chain_and_sign(event)
        
        # Store all three elements
        self.events.append((event, chain_hash, signature))
        
        return {
            "event": event,
            "signature": signature.hex(),
            "chain_hash": chain_hash
        }
    
    def delete(self, file_hash, user_id="admin"):
        """Simulate file deletion"""
        file_path = os.path.join(self.uploads_dir, file_hash)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        event = {
            "action": "delete",
            "file_hash": file_hash,
            "timestamp": time.time(),
            "user_id": user_id
        }
        
        chain_hash, signature = self.hsm.chain_and_sign(event)
        self.events.append((event, chain_hash, signature))
        
        return {"event": event, "signature": signature.hex()}
    
    def batch_and_publish(self):
        """Simulate 10-minute batch commit"""
        if not self.events:
            print("No events to batch")
            return
        
        # Unpack 3 elements correctly
        event_hashes = [sha256(e) for e, _, _ in self.events]
        merkle_root = build_merkle_tree(event_hashes)
        
        final_chain_hash = self.hsm.get_latest_hash()
        prev_batch_hash = sha256(f"batch_{self.batch_number-1}") if self.batch_number > 0 else sha256("genesis")
        
        batch_header = {
            "batch_number": self.batch_number,
            "merkle_root": merkle_root,
            "final_chain_hash": final_chain_hash,
            "previous_batch_header_hash": prev_batch_hash,
            "timestamp": time.time()
        }
        
        batch_signature = sign(json.dumps(batch_header), self.hsm.private_key)
        
        # Package with all three elements
        batch_package = {
            "header": batch_header,
            "signature": batch_signature.hex(),
            "events": [{"event": e, "signature": sig.hex(), "chain_hash": h} for e, h, sig in self.events]
        }
        
        # Publish to witnesses
        for i in range(1, 4):
            witness_file = os.path.join(self.witness_dir, f"witness{i}.txt")
            with open(witness_file, 'a') as f:
                f.write(json.dumps(batch_package) + "\n")
        
        print(f"Batch {self.batch_number} published to witnesses")
        print(f"  Merkle Root: {merkle_root[:32]}...")
        print(f"  Events: {len(self.events)}")
        
        self.events.clear()
        self.batch_number += 1
        
        return batch_package
    
    def load_previous_batch_header(self):
        """Load previous batch header from witness1"""
        witness_file = os.path.join(self.witness_dir, "witness1.txt")
        if not os.path.exists(witness_file):
            return None
        
        with open(witness_file, 'r') as f:
            lines = f.readlines()
            if not lines:
                return None
            last_line = lines[-1].strip()
            if not last_line:
                return None
            batch = json.loads(last_line)
            return batch.get("header", {})
    
    def download(self, file_hash):
        """Simulate file download with verification package"""
        file_path = os.path.join(self.uploads_dir, file_hash)
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Search through ALL batches across all witnesses
        for witness_id in range(1, 4):
            witness_file = os.path.join(self.witness_dir, f"witness{witness_id}.txt")
            if not os.path.exists(witness_file):
                continue
            
            with open(witness_file, 'r') as f:
                for line in f:
                    batch = json.loads(line)
                    # Search events in this batch
                    for event_data in batch["events"]:
                        if (event_data["event"]["file_hash"] == file_hash and 
                            event_data["event"]["action"] == "upload"):
                            # Return the batch that CONTAINS this event
                            return {
                                "file_content": file_content,
                                "event": event_data["event"],
                                "signature": event_data["signature"],
                                "merkle_proof": {"event_index": 0},
                                "latest_batch": batch  # This is the CORRECT batch
                            }
        
        return None