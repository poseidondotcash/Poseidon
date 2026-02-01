pragma circom 2.0.0;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/bitify.circom";

/******************************************
 * Merkle Tree Module
 *
 * Poseidon-based binary Merkle tree
 * operations for membership proofs.
 ******************************************/

/******************************************
 * Poseidon 2-ary Merkle hash
 ******************************************/

template PoseidonHash2() {
    signal input left;
    signal input right;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    out <== h.out;
}

/******************************************
 * Merkle path verifier (2-ary, Poseidon)
 *
 * Inputs:
 *  - leaf: the note commitment (field element)
 *  - pathElements[depth]: sibling nodes
 *  - pathIndex[depth]: 0 if current is left child, 1 if right
 *
 * Output:
 *  - root: recomputed Merkle root
 ******************************************/

template MerklePath(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndex[depth]; // 0 or 1
    signal output root;

    // cur[0] = leaf, cur[depth] = root
    signal cur[depth + 1];
    cur[0] <== leaf;

    component h[depth];
    component idxBits[depth];
    signal left[depth];
    signal right[depth];

    for (var i = 0; i < depth; i++) {
        // Constrain pathIndex[i] to {0,1}
        idxBits[i] = Num2Bits(1);
        idxBits[i].in <== pathIndex[i];

        h[i] = PoseidonHash2();

        // Single-product form:
        // left = cur + (sib - cur)*b
        // right = sib + (cur - sib)*b
        left[i]  <== cur[i] + (pathElements[i] - cur[i]) * pathIndex[i];
        right[i] <== pathElements[i] + (cur[i] - pathElements[i]) * pathIndex[i];

        h[i].left  <== left[i];
        h[i].right <== right[i];

        cur[i + 1] <== h[i].out;
    }

    root <== cur[depth];
}
