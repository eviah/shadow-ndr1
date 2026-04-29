// Tests for the ZK tenant-membership verifier. Run with `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyProof,
  verifyOrThrow,
  buildMerklePath,
  poseidonLikeHash,
} from '../src/services/zkVerifier.js';

const wellFormedProof = () => ({
  pi_a: ['1', '2', '1'],
  pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
  pi_c: ['7', '8', '1'],
  protocol: 'groth16',
  curve: 'bn128',
});

test('rejects null/undefined proof', async () => {
  const r1 = await verifyProof(null, ['1', '2', '3']);
  assert.equal(r1.valid, false);
  const r2 = await verifyProof(undefined, ['1', '2', '3']);
  assert.equal(r2.valid, false);
});

test('rejects wrong public signal count', async () => {
  const r = await verifyProof(wellFormedProof(), ['1', '2']);
  assert.equal(r.valid, false);
  assert.match(r.reason, /3 public signals/);
});

test('rejects non-decimal public signals', async () => {
  const r = await verifyProof(wellFormedProof(), ['0xdeadbeef', '2', '3']);
  assert.equal(r.valid, false);
});

test('rejects non-groth16 protocol', async () => {
  const proof = wellFormedProof();
  proof.protocol = 'plonk';
  const r = await verifyProof(proof, ['1', '2', '3']);
  assert.equal(r.valid, false);
});

test('accepts well-formed structural envelope when snarkjs unavailable', async () => {
  const r = await verifyProof(wellFormedProof(), ['1', '2', '3']);
  assert.ok(r.valid);
  assert.equal(r.mode, 'structural');
});

test('verifyOrThrow throws when snarkjs is required but unavailable', async () => {
  await assert.rejects(
    () => verifyOrThrow(wellFormedProof(), ['1', '2', '3'], { vkey: null }),
    /ZK_REJECTED|zk membership rejected/,
  );
});

test('buildMerklePath produces correct depth + indices', () => {
  const leaves = ['100', '200', '300', '400'];
  const { root, pathElements, pathIndices } = buildMerklePath(2, leaves, 4);
  assert.equal(pathElements.length, 4, 'path depth must equal K');
  assert.equal(pathIndices.length, 4);
  // index 2 (0b010) → indices bottom-up: 0, 1, 0, 0
  assert.deepEqual(pathIndices, ['0', '1', '0', '0']);
  assert.match(root, /^[0-9]+$/);
});

test('poseidonLikeHash is deterministic', () => {
  const a = poseidonLikeHash('foo', 'bar');
  const b = poseidonLikeHash('foo', 'bar');
  const c = poseidonLikeHash('foo', 'baz');
  assert.equal(a, b);
  assert.notEqual(a, c);
});
