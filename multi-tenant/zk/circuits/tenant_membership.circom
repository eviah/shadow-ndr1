pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

// TenantMembership
// =================
// Prove that a tenant's data record belongs to the tenant's Merkle root,
// without revealing:
//   * which leaf in the tree the record sits at
//   * any of the sibling hashes
//   * the actual tenant id (only its commitment is public)
//
// Public inputs:
//   tenantRoot       — Merkle root of the tenant's data tree
//   tenantCommitment — Poseidon hash of (tenantId, salt)
//   recordTag        — public tag identifying *which* record we're proving
//                      membership for (binds the proof to a specific lookup)
//
// Private inputs:
//   tenantId        — the actual tenant identifier (not revealed)
//   salt            — randomness used in tenantCommitment (not revealed)
//   leaf            — Poseidon(recordTag, payloadHash) for the data row
//   payloadHash     — hash of the record contents
//   pathElements[K] — sibling hashes along the Merkle path
//   pathIndices[K]  — bit per level: 0 = sibling on right, 1 = sibling on left
//
// Constraints:
//   1. tenantCommitment == Poseidon(tenantId, salt)
//   2. leaf == Poseidon(recordTag, payloadHash)
//   3. Folding `leaf` up the path with the siblings reproduces tenantRoot

template TenantMembership(K) {
    // Public
    signal input  tenantRoot;
    signal input  tenantCommitment;
    signal input  recordTag;

    // Private
    signal input  tenantId;
    signal input  salt;
    signal input  payloadHash;
    signal input  pathElements[K];
    signal input  pathIndices[K];

    // 1. Bind the proof to the tenant identity commitment.
    component commitH = Poseidon(2);
    commitH.inputs[0] <== tenantId;
    commitH.inputs[1] <== salt;
    commitH.out === tenantCommitment;

    // 2. Compute the leaf hash from (recordTag, payloadHash).
    component leafH = Poseidon(2);
    leafH.inputs[0] <== recordTag;
    leafH.inputs[1] <== payloadHash;

    // 3. Fold leaf up the tree using pathElements / pathIndices.
    signal cur[K + 1];
    cur[0] <== leafH.out;

    component muxL[K];
    component muxR[K];
    component levelH[K];

    for (var i = 0; i < K; i++) {
        // pathIndices[i] must be a bit
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        // (left, right) = pathIndices[i] == 0 ? (cur, sibling) : (sibling, cur)
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s    <== pathIndices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].s    <== pathIndices[i];

        levelH[i] = Poseidon(2);
        levelH[i].inputs[0] <== muxL[i].out;
        levelH[i].inputs[1] <== muxR[i].out;

        cur[i + 1] <== levelH[i].out;
    }

    // 4. Final accumulator must equal the public root.
    cur[K] === tenantRoot;
}

component main {
    public [tenantRoot, tenantCommitment, recordTag]
} = TenantMembership(20);
