# VeriDoc
*A System for Verifiable Integrity in Public Document Archives*

CS-3610 (Information Security) Course Project-cum-Assignment

## 🎯 Overview

VeriDoc implements a cryptographic document archive that provides end-to-end integrity guarantees through hardware-backed signing, Merkle tree batching, and federated witness logs. Every file operation is cryptographically signed, creating an immutable, verifiable chain of events that can detect both tampering and silent deletion attacks.

**Core Security Properties:**
- ✅ **Content Integrity**: SHA-256 addressing detects any file modification
- ✅ **Event Authenticity**: ECDSA P-384 signatures from HSM-protected keys
- ✅ **Batch Inclusion**: Merkle tree proofs confirm events belong to published batches
- ✅ **Public Verifiability**: 3 independent witness logs provide audit trails
- ✅ **Attack Detection**: Actively detects tampering & unauthorized deletions

## 📁 Directory Structure

```
project/
├── main.py                 # Driver script with attack simulations
├── server.py               # Public Records Server logic
├── client.py               # Client verification & audit logic
├── hsm_sim.py              # Simulated HSM/TPM for secure signing
├── utils.py                # Crypto primitives (SHA-256, ECDSA, Merkle)
├── keys/                   # Cryptographic keys (auto-generated)
│   ├── private_key.pem     # Simulated HSM private key
│   └── public_key.pem      # Public key for client verification
├── uploads/                # Content-addressed object store
└── witness_logs/           # Federated witness logs (3 replicas)
    ├── witness1.txt
    ├── witness2.txt
    └── witness3.txt

```

## 🚀 Quick Start

### Prerequisites

```bash
pip install cryptography
```

### Run the Security Simulation

```bash
python main.py
```

The simulation demonstrates a complete document lifecycle with active attack scenarios:
- Multi-file upload and batch publishing
- Document versioning (updates create new events)
- **Tampering attack detection** (Check 1: Content Integrity)
- **Silent deletion audit** (finding unauthorized deletions)
- Chain hash progression across all operations

## 🔒 Architecture & Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                    PublicRecordsServer                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Upload   │→│ HSM Sign │→│  Batch   │→│ Witness  │   │
│  │ Handler  │  │ & Chain  │  │ Merkle   │  │ Publish  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│         ↓         │   persistent log    │  3 replicas    │
│         └─────────┼──→ events/          └─→ witness1-3   │
│                   └─→ in-memory state                     │
└─────────────────────────────────────────────────────────────┘
         ↑                                              ↓
         │                                              ↓
┌────────┴────────┐                         ┌───────────────┐
│  Client         │                         │  Immutable    │
│  Verifier       │←────────────────────────│  Witness      │
│  (4-step check) │  searches all batches   │  Logs         │
└─────────────────┘                         └───────────────┘
```

### The 4-Step Verification Protocol

Every download undergoes rigorous client-side verification:

```python
1. Content Integrity: SHA256(file_content) == event.file_hash?
2. Event Authenticity: ECDSA_Verify(event, signature, public_key)?
3. Batch Inclusion: Event ∈ Merkle_Tree(batch.events)?
4. Public Witness: Batch exists in ≥ 1 witness logs?
```

## 📋 Simulation Walkthrough

1. **Upload 3 Documents**: `doc1.txt`, `doc2.txt`, `doc3.txt`
   - Each generates a Signed Upload Receipt (SUR)
   - Events persisted to `events/current_batch.log` (crash-safe)
   - HSM chain updates: `Hash₁ → Hash₂ → Hash₃`

2. **Batch 0 Publication**: All 3 events batched into Merkle tree
   - Signed batch header anchors HSM state
   - Published to all 3 witness logs

3. **Document Update**: Modify `doc1.txt` → new upload event
   - Original version remains in Batch 0
   - Updated version creates Hash₄ (versioning preserved)

4. **Batch 1 Publication**: Update event in new batch
   - Links to Batch 0 via previous header hash
   - Demonstrates inter-batch chaining

5. **Verify Untouched File**: `doc3.txt` passes all 4 checks
   - Cryptographic proof of authenticity across batches

6. **Tampering Attack**: Direct file modification in `uploads/`
   - **Detection**: Check 1 fails (content hash mismatch)
   - Signature valid, but content provably corrupted

7. **Silent Deletion Attack**: Delete `doc2.txt` without logging
   - **Detection**: Audit finds upload event but no delete event
   - Witness logs provide immutable evidence of unauthorized deletion

8. **Chain Summary**: Shows cryptographic progression of all events
   - Each hash depends on entire history

## ⚠️ Important Security Note

**Known Vulnerability**: The `events/current_batch.log` file is currently stored in **plaintext**. An adversary with file system access could:

1. Modify the log before server restart
2. Corrupt the HSM's `latest_event_hash` on state restoration
3. Insert fraudulent events that get batched and signed

**This IS NOT detected by witness audit logs** because tampering occurs *before* witness publication.

**Mitigation**: In production, the event log must be:
- Stored within the HSM trust boundary
- Or HSM-signed before writing to disk
- Or use a hardware-protected write-ahead log

This is acknowledged as a simulation limitation for academic demonstration.

## 🔑 Cryptographic Details

- **Hashing**: SHA-256 (content addressing, Merkle trees, chain links)
- **Signatures**: ECDSA with P-384 curve
- **Merkle Tree**: Binary concatenation construction
- **Chain Linking**: `Hash_N = SHA256(SHA256(Event) + Hash_N-1)`
- **Batch Linking**: `prev_batch_header_hash` in batch header

## 📊 Performance & Scalability

- **Batching**: 10-minute intervals (simulated as immediate in demo)
- **Verification**: O(log n) with Merkle proofs (simplified in simulation)
- **Storage**: Content-addressed deduplication
- **Witness**: 3 replicas for Byzantine fault tolerance

## 🎓 Academic Context

This project demonstrates key Information Security concepts:

- **Chains of Custody**: Cryptographic event linking
- **Merkle Trees**: Efficient batch commitments
- **Hardware Security**: HSM key isolation
- **Byzantine Fault Tolerance**: Multi-witness publication
- **Non-Repudiation**: Digital signatures on all actions
- **Forensic Audit**: Immutable logs for post-incident analysis

## 🔧 Potential Enhancements

- HSM-encrypted write-ahead log for crash safety
- Networked witness gossip protocol
- Full Merkle path generation/verification
- Real-time batch timer (10-minute intervals)
- Distributed consensus for witness logs
- UI for document upload/verification
- Batch compaction and archival

## 📄 License

MIT License - Academic use encouraged.

## 🤝 Contributing

This is a course project. For educational inquiries, please open an issue.

---

**Run it yourself**: `python main.py`