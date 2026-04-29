# Shadow NDR — Zero-Knowledge Multi-Tenancy

The `tenant_membership.circom` circuit lets a tenant prove "this threat
record belongs to me" without revealing **which** of their records it is
or **who** they are at the network level — only a Poseidon commitment of
the tenant id is exposed.

## Why

In aviation security, threat ingestion has to honor regulatory boundaries:
EL AL queries must not be observable to Israir / Arkia, and vice-versa.
The naive solution (one DB role per tenant + RLS) leaks **timing** and
**access-pattern** information. ZK membership proofs let the audit trail
record *that* tenant T queried record R without recording either side.

## Build

Requires `circom` 2.1+, `snarkjs` 0.7+, and `circomlib` (npm).

```bash
# 1. Install toolchain
npm install -g circom snarkjs
npm install circomlib

# 2. Compile circuit -> R1CS + WASM witness generator
circom tenant_membership.circom --r1cs --wasm --sym

# 3. Powers-of-tau ceremony (use the universal Hermez ptau for K=20)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau

# 4. Phase-2 setup -> proving + verifying keys
snarkjs groth16 setup tenant_membership.r1cs powersOfTau28_hez_final_18.ptau \
    tenant_membership_0000.zkey
snarkjs zkey contribute tenant_membership_0000.zkey tenant_membership_final.zkey \
    --name="shadow-ndr first contribution"
snarkjs zkey export verificationkey tenant_membership_final.zkey verification_key.json

# 5. Use the verifier from Node:
#    backend/src/services/zkVerifier.js
```

## Public vs Private inputs

| Input              | Visibility | Purpose                              |
|--------------------|------------|--------------------------------------|
| `tenantRoot`       | public     | Tenant's data Merkle root            |
| `tenantCommitment` | public     | Poseidon(tenantId, salt)             |
| `recordTag`        | public     | Which record this proof refers to    |
| `tenantId`         | private    | Real tenant id (never leaked)        |
| `salt`             | private    | Commitment randomness                |
| `payloadHash`      | private    | Hash of the record contents          |
| `pathElements[]`   | private    | Merkle siblings (20 levels = 2^20)   |
| `pathIndices[]`    | private    | Direction bits along the path        |

## Test plan

The Node verifier exposes both `verify(proof, publicSignals)` (pure) and
`buildPath(leafIdx, leaves)` (helper for offline tests). The unit test in
`backend/test/zk-verifier.mjs` covers:

* malformed proof → reject
* wrong public root → reject
* genuine proof → accept
