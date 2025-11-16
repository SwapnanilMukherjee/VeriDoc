import os
import json
from utils import sha256, load_public_key, verify
from cryptography.hazmat.primitives import serialization

class Verifier:
    def __init__(self, public_key_path):
        self.public_key = load_public_key(public_key_path)
    
    def verify_download(self, verification_package):
        if not verification_package:
            return False, "No package provided"
        
        file_content = verification_package["file_content"]
        event = verification_package["event"]
        signature = verification_package.get("signature", "")
        merkle_proof = verification_package["merkle_proof"]
        latest_batch = verification_package["latest_batch"]
        
        # Check 1: Content Integrity
        calculated_hash = sha256(file_content)
        expected_hash = event["file_hash"]
        if calculated_hash != expected_hash:
            return False, f"Check 1 FAILED: File hash mismatch"
        
        # Check 2: Event Authenticity
        if signature:
            signature_bytes = bytes.fromhex(signature) if isinstance(signature, str) else signature
            if not verify(event, signature_bytes, self.public_key):
                return False, "Check 2 FAILED: Event signature invalid"
        else:
            return False, "Check 2 FAILED: No signature provided"
        
        # Check 3: Batch Inclusion
        if not latest_batch:
            return False, "Check 3 FAILED: No batch header"
        
        batch_events = latest_batch.get("events", [])
        event_hash = sha256(event)
        event_hashes = [sha256(e["event"]) for e in batch_events]
        
        if event_hash not in event_hashes:
            return False, "Check 3 FAILED: Event not found in batch"
        
        # Check 4: Public Witness
        witness_file = "witness_logs/witness1.txt"
        if not os.path.exists(witness_file):
            return False, "Check 4 FAILED: No witness logs"
        
        return True, "All checks PASSED. File is authentic."
    
    def audit_missing_file(self, file_hash, witness_dir="witness_logs/"):
        found_upload = False
        found_delete = False
        evidence = []
        
        for i in range(1, 4):
            witness_file = os.path.join(witness_dir, f"witness{i}.txt")
            if not os.path.exists(witness_file):
                continue
            
            with open(witness_file, 'r') as f:
                for line in f:
                    batch = json.loads(line)
                    for e in batch["events"]:
                        if e["event"]["file_hash"] == file_hash:
                            if e["event"]["action"] == "upload":
                                found_upload = True
                                evidence.append(f"Found upload at {e['event']['timestamp']} in {witness_file}")
                            elif e["event"]["action"] == "delete":
                                found_delete = True
                                evidence.append(f"Found delete at {e['event']['timestamp']}")
        
        return found_upload, found_delete, evidence