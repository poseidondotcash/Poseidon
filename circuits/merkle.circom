pragma circom 2.0.0;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/bitify.circom";

template PoseidonHash2() {
    signal input left;
    signal input right;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    out <== h.out;
}

template MerklePath(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndex[depth];
    signal output root;

    signal cur[depth + 1];
    cur[0] <== leaf;

    component h[depth];
    component idxBits[depth];
    signal left[depth];
    signal right[depth];

    for (var i = 0; i < depth; i++) {
        idxBits[i] = Num2Bits(1);
        idxBits[i].in <== pathIndex[i];

        h[i] = PoseidonHash2();

        left[i]  <== cur[i] + (pathElements[i] - cur[i]) * pathIndex[i];
        right[i] <== pathElements[i] + (cur[i] - pathElements[i]) * pathIndex[i];

        h[i].left  <== left[i];
        h[i].right <== right[i];

        cur[i + 1] <== h[i].out;
    }

    root <== cur[depth];
}
