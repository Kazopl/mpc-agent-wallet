# Security Model

This guide covers the security model, threat analysis and how the MPC Agent Wallet SDK protects against attacks.

## Overview

The MPC Agent Wallet gives AI agents secure cryptocurrency wallet access while keeping humans in control.

### Security Goals

1. **Key Security**: Private keys are never reconstructed or exposed
2. **Access Control**: AI agents cannot act unilaterally
3. **Policy Enforcement**: Transactions comply with configured policies
4. **Availability**: System remains operational under attack
5. **Auditability**: All operations are traceable

## Trust Model

### Parties and Roles

| Party | Trust Level | Responsibilities |
|-------|-------------|------------------|
| **Agent** | Semi-trusted | Starts transactions, enforces client-side policy |
| **User** | Trusted | Primary approval authority, manages policy |
| **Recovery** | Trusted (offline) | Backup approval, key recovery |
| **Relay** | Untrusted | Message routing only (cannot access secrets) |

### Threshold Security

The 2-of-3 threshold ensures:

- **Agent compromise**: Attacker cannot sign without user OR recovery
- **User device loss**: Agent + recovery can recover funds
- **Single point compromise**: No single party can authorize transactions

```
Attack Scenarios:
┌──────────────────────────────┬───────┬──────┬──────────┬──────┐
│ Scenario                     │ Agent │ User │ Recovery │ Safe │
├──────────────────────────────┼───────┼──────┼──────────┼──────┤
│ Agent compromised            │   ✗   │  ✓   │    ✓     │  ✓   │
│ User device stolen           │   ✓   │  ✗   │    ✓     │  ✓   │
│ Recovery guardian corrupt    │   ✓   │  ✓   │    ✗     │  ✓   │
│ Agent + User compromised     │   ✗   │  ✗   │    ✓     │  ✗   │
│ Agent + Recovery compromised │   ✗   │  ✓   │    ✗     │  ✗   │
│ User + Recovery compromised  │   ✓   │  ✗   │    ✗     │  ✗   │
└──────────────────────────────┴───────┴──────┴──────────┴──────┘
```

## Threat Analysis

### T1: AI Agent Compromise

**Threat**: Attacker gains control of the AI agent and its key share.

**Mitigations**:
- [x] 2-of-3 threshold prevents unilateral signing
- [x] Policy engine limits transaction scope (even if compromised)
- [x] Spending limits cap potential losses
- [x] Whitelist restricts recipient addresses
- [x] User notifications for all signing requests

**Residual Risk**: Low - Attacker needs to compromise second party.

### T2: Man-in-the-Middle on Relay

**Threat**: Attacker intercepts/modifies MPC protocol messages.

**Mitigations**:
- [x] MPC protocol authenticated (VSS commitments)
- [x] Message integrity via cryptographic hashing
- [x] Session IDs prevent replay attacks
- [x] TLS encryption for relay connections
- [ ] Certificate pinning (recommended)

**Residual Risk**: Low - Protocol-level authentication prevents MITM.

### T3: Key Share Extraction

**Threat**: Attacker extracts encrypted key share from storage.

**Mitigations**:
- [x] ChaCha20-Poly1305 encryption at rest
- [x] Password-based key derivation (Argon2id)
- [x] Secure file permissions (0600)
- [ ] Hardware security module (optional)
- [ ] TEE enclave storage (optional)

**Residual Risk**: Medium - Depends on password strength and storage security.

### T4: Policy Bypass

**Threat**: Attacker crafts transactions that circumvent policy rules.

**Mitigations**:
- [x] Policy evaluated before MPC signing begins
- [x] On-chain spending limits as backup
- [x] Contract interaction restrictions
- [x] Fuzz testing of policy engine

**Residual Risk**: Low - Multiple layers of policy enforcement.

### T5: Replay Attack

**Threat**: Attacker replays previously signed transactions.

**Mitigations**:
- [x] Session IDs bound to protocol execution
- [x] Nonce management for EVM transactions
- [x] Recent blockhash for Solana transactions

**Residual Risk**: Very Low - Standard blockchain replay protection.

### T6: Denial of Service

**Threat**: Attacker prevents legitimate signing operations.

**Mitigations**:
- [x] Rate limiting on relay endpoints
- [x] Session timeouts prevent resource exhaustion
- [x] Webhook retry logic with exponential backoff
- [ ] Redundant relay deployment (recommended)

**Residual Risk**: Medium - DoS on relay affects availability.

### T7: Social Engineering

**Threat**: Attacker tricks user into approving malicious transaction.

**Mitigations**:
- [x] Clear transaction details in approval UI
- [x] Contract address verification
- [x] Value/recipient highlighting
- [ ] Phishing-resistant authentication (optional)

**Residual Risk**: Medium - Depends on user awareness.

### T8: Supply Chain Attack

**Threat**: Malicious code in dependencies.

**Mitigations**:
- [x] Minimal dependency footprint
- [x] Dependency auditing with `cargo audit`
- [x] Lock files for reproducible builds
- [ ] SBOM generation (planned)

**Residual Risk**: Low - Regular auditing mitigates risk.

## Cryptographic Guarantees

### MPC Protocol (DKLs23)

| Property | Guarantee |
|----------|-----------|
| **Correctness** | Protocol produces valid ECDSA signatures |
| **Secrecy** | Key shares reveal nothing about private key |
| **Robustness** | Malicious parties detected and rejected |
| **UC Security** | Secure under universal composability |

### Key Derivation

```
Password → Argon2id(password, salt, iterations=3, memory=64MB) → Encryption Key
```

Parameters:
- **Salt**: 32 random bytes per key share
- **Iterations**: 3 (memory-hard)
- **Memory**: 64 MB
- **Parallelism**: 4

### Encryption

```
EncryptedKeyShare = ChaCha20-Poly1305(key, nonce, plaintext)
```

- **Key**: 256 bits (from Argon2id)
- **Nonce**: 96 bits (random, unique per encryption)
- **Tag**: 128 bits (authentication tag)

## Operational Security

### Key Share Backup

**Recommended Approach**:

1. Encrypt key share with strong password
2. Split backup into multiple pieces (Shamir's Secret Sharing)
3. Store pieces in geographically distributed locations
4. Test recovery procedure annually

### Incident Response

| Scenario | Response |
|----------|----------|
| Agent key share compromised | Rotate agent share via recovery + user |
| User device lost | Recover via agent + recovery |
| Recovery guardian compromised | Initiate share refresh with agent + user |
| Policy breach detected | Pause signing, review logs, update policy |

### Monitoring Recommendations

1. **Transaction Monitoring**: Alert on unusual patterns
2. **Policy Violations**: Log and alert on rejected transactions
3. **Session Anomalies**: Track failed signing attempts
4. **Key Access**: Audit key share decryption events

## Compliance Considerations

### Data Protection

- Key shares are personal data under GDPR
- Implement data deletion procedures
- Document data flows and storage

### Financial Regulations

- Consider licensing requirements for custody
- Implement KYT (Know Your Transaction) where required
- Maintain audit trails for regulatory review

## References

1. [DKLs23: Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2023/765)
2. [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
3. [NIST SP 800-57: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
4. [EIP-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
5. [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
