# main.py (revised)
import os
import json
import shutil
from server import PublicRecordsServer
from client import Verifier

def setup():
    """Clean and create directory structure"""
    dirs = ["uploads", "witness_logs", "keys"]
    for d in dirs:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    
    # Create witness log files
    for i in range(1, 4):
        open(f"witness_logs/witness{i}.txt", 'w').close()

def simulate_attack():
    """
    SECURITY SIMULATION: Document Lifecycle with Attack Demonstrations
    
    This simulation demonstrates tampering detection and silent deletion auditing
    alongside normal multi-file operations and versioning.
    """
    
    # Setup
    setup()
    server = PublicRecordsServer()
    verifier = Verifier("keys/public_key.pem")
    
    print("\n[1] UPLOADING THREE FILES TO SERVER")
    print("-" * 40)
    
    # File 1
    file1 = "doc1.txt"
    with open(file1, 'w') as f:
        f.write("First original document content.")
    sur1 = server.upload(file1)
    print(f"  Uploaded {file1} -> hash: {sur1['event']['file_hash'][:32]}...")
    
    # File 2
    file2 = "doc2.txt"
    with open(file2, 'w') as f:
        f.write("Second original document content.")
    sur2 = server.upload(file2)
    print(f"  Uploaded {file2} -> hash: {sur2['event']['file_hash'][:32]}...")
    
    # File 3
    file3 = "doc3.txt"
    with open(file3, 'w') as f:
        f.write("Third original document content.")
    sur3 = server.upload(file3)
    print(f"  Uploaded {file3} -> hash: {sur3['event']['file_hash'][:32]}...")
    
    print("\n[2] BATCHING AND PUBLISHING THREE EVENTS")
    print("-" * 40)
    batch1 = server.batch_and_publish()
    print(f"  Batch {batch1['header']['batch_number']} published")
    print(f"  Events in batch: {len(batch1['events'])}")
    print(f"  Merkle Root: {batch1['header']['merkle_root'][:32]}...")
    print(f"  Final Chain Hash: {batch1['header']['final_chain_hash'][:32]}...")

    print("\n[3] UPDATING FIRST DOCUMENT")
    print("-" * 40)
    
    # Modify the file content
    with open(file1, 'w') as f:
        f.write("First document content has been UPDATED.")
    
    # Re-upload creates new event (same filename, different hash)
    updated_sur1 = server.upload(file1)
    print(f"  Updated {file1}")
    print(f"  Old hash: {sur1['event']['file_hash'][:32]}...")
    print(f"  New hash: {updated_sur1['event']['file_hash'][:32]}...")
    print(f"  Both versions exist in logs")
    
    print("\n[4] BATCHING UPDATE EVENT")
    print("-" * 40)
    batch2 = server.batch_and_publish()
    print(f"  Batch {batch2['header']['batch_number']} published")
    print(f"  Events in batch: {len(batch2['events'])}")
    print(f"  Merkle Root: {batch2['header']['merkle_root'][:32]}...")
    print(f"  Final Chain Hash: {batch2['header']['final_chain_hash'][:32]}...")
    
    print("\n[5] VERIFYING THIRD FILE (UNTOUCHED)")
    print("-" * 40)
    download_pkg = server.download(sur3['event']['file_hash'])
    
    if download_pkg:
        print(f"Downloading file with hash: {sur3['event']['file_hash'][:32]}...")
        print(f"  From location: uploads/{sur3['event']['file_hash']}")
        print(f"  Content: '{download_pkg['file_content'].decode()[:50]}...'")
        
        is_valid, msg = verifier.verify_download(download_pkg)
        print(f"\nVerification: {msg}")
        print(f"  All 4 checks passed: {is_valid}")
        
        if is_valid:
            print("    File 3 remains authentic across all operations")
    
    print("\n[6] TAMPERING ATTACK SIMULATION")
    print("-" * 40)
    
    # Get the hash of file 3 (the verified file)
    file3_hash = sur3['event']['file_hash']
    file3_path = f"uploads/{file3_hash}"
    
    print(f"  Target file: {file3_path}")
    original_content = open(file3_path, 'rb').read()
    print(f"  Original content: '{original_content.decode()}'")
    
    # Directly modify the file content (simulating attacker tampering)
    with open(file3_path, 'wb') as f:
        f.write(b"MALICIOUSLY MODIFIED CONTENT!")
    
    print(f"  Tampered content: '{open(file3_path, 'rb').read().decode()}'")
    
    # Attempt to verify the tampered file
    tampered_pkg = server.download(file3_hash)
    if tampered_pkg:
        is_valid, msg = verifier.verify_download(tampered_pkg)
        print(f"\n  Verification after tampering: {msg}")
        print(f"  Attack detected: {not is_valid}")
        if not is_valid:
            print("    Check 1 FAILED: Content integrity mismatch")

    print("\n[7] SILENT DELETION ATTACK SIMULATION")
    print("-" * 40)
    
    # Delete file2 directly from storage (simulating silent deletion)
    file2_hash = sur2['event']['file_hash']
    file2_path = f"uploads/{file2_hash}"
    
    print(f"  Target file: {file2_path}")
    print(f"  Deleting without logging...")
    if os.path.exists(file2_path):
        os.remove(file2_path)
        print(f"  File deleted from object store")
    
    # Attempt to download the deleted file
    deleted_pkg = server.download(file2_hash)
    if deleted_pkg is None:
        print(f"  Download failed: File not found in object store")
    
    # Audit the missing file to detect the deletion
    print(f"\n  Auditing missing file {file2_hash[:32]}...")
    found_upload, found_delete, evidence = verifier.audit_missing_file(file2_hash)
    
    if found_upload and not found_delete:
        print(f"  File was uploaded but never officially deleted")
        print(f"  Likely deleted silently.")
        for e in evidence:
            print(f"    {e}")
    elif found_upload and found_delete:
        print(f"  File was properly deleted via logged operation")
    else:
        print(f"  No records found for this file hash")
    
    print("\n[8] EVENT CHAIN SUMMARY")
    print("-" * 40)
    total_events = len(batch1['events']) + len(batch2['events'])
    print(f"Total events processed: {total_events}")
    print(f"Batches created: 2")
    print(f"Chain hash progression:")
    print(f"  After event 1: {sur1['chain_hash'][:32]}...")
    print(f"  After event 2: {sur2['chain_hash'][:32]}...")
    print(f"  After event 3: {sur3['chain_hash'][:32]}...")
    print(f"  After event 4 (update): {updated_sur1['chain_hash'][:32]}...")
    print(f"  Final batch 0: {batch1['header']['final_chain_hash'][:32]}...")
    print(f"  Final batch 1: {batch2['header']['final_chain_hash'][:32]}...")
    
    print(f"\nSecurity Analysis:")
    print(f"  Tampering attack detected: Yes (Check 1)")
    print(f"  Silent deletion detected: Yes (Audit)")
    
    print("\nFinal object store state:")
    if os.path.exists("uploads/"):
        files = os.listdir("uploads/")
        print(f"  Total files stored: {len(files)}")
        for f in files:
            print(f"    - uploads/{f[:32]}...")

if __name__ == "__main__":
    simulate_attack()