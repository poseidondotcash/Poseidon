pragma circom 2.0.0;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";

include "utils.circom";
include "merkle.circom";

template PrivateStealthJoinSplit(nIns, nOuts, depth) {
    signal input inBalance[nIns];
    signal input inSpendNonce[nIns];
    signal input inNoteNonce[nIns];
    signal input receiverViewPriv;

    signal input inPathElements[nIns][depth];
    signal input inPathIndex[nIns][depth];

    signal input outAmount[nOuts];
    signal input outNoteNonce[nOuts];

    signal input merkleRoot;
    signal input inputNullifier[nIns];
    signal input destLimbs[4];
    signal input outputCommitment[nOuts];
    signal input publicAmount;
    signal input extAmountIn;

    component inBalRC[nIns];
    for (var i = 0; i < nIns; i++) {
        inBalRC[i] = RangeCheckAmount(64);
        inBalRC[i].v <== inBalance[i];
    }

    component outAmtRC[nOuts];
    for (var j = 0; j < nOuts; j++) {
        outAmtRC[j] = RangeCheckAmount(64);
        outAmtRC[j].v <== outAmount[j];
    }

    component extRC = RangeCheckAmount(64);
    extRC.v <== extAmountIn;

    component pubRC = RangeCheckAmount(64);
    pubRC.v <== publicAmount;

    component sumIn = SumN(nIns);
    component sumOut = SumN(nOuts);

    for (var i2 = 0; i2 < nIns; i2++) {
        sumIn.in[i2] <== inBalance[i2];
    }
    for (var j2 = 0; j2 < nOuts; j2++) {
        sumOut.in[j2] <== outAmount[j2];
    }

    sumIn.out + extAmountIn === sumOut.out + publicAmount;

    component inCommitPoseidon[nIns];
    component inPath[nIns];
    component isZeroBalance[nIns];

    for (var i3 = 0; i3 < nIns; i3++) {
        inCommitPoseidon[i3] = Poseidon(2);
        inCommitPoseidon[i3].inputs[0] <== inBalance[i3];
        inCommitPoseidon[i3].inputs[1] <== inNoteNonce[i3];

        isZeroBalance[i3] = IsZero();
        isZeroBalance[i3].in <== inBalance[i3];

        inPath[i3] = MerklePath(depth);
        inPath[i3].leaf <== inCommitPoseidon[i3].out;

        for (var d = 0; d < depth; d++) {
            inPath[i3].pathElements[d] <== inPathElements[i3][d];
            inPath[i3].pathIndex[d]   <== inPathIndex[i3][d];
        }

        (1 - isZeroBalance[i3].out) * (inPath[i3].root - merkleRoot) === 0;
    }

    component outCommitPoseidon[nOuts];
    for (var k = 0; k < nOuts; k++) {
        outCommitPoseidon[k] = Poseidon(2);
        outCommitPoseidon[k].inputs[0] <== outAmount[k];
        outCommitPoseidon[k].inputs[1] <== outNoteNonce[k];
        outCommitPoseidon[k].out === outputCommitment[k];
    }

    component destRC[4];
    for (var d = 0; d < 4; d++) {
        destRC[d] = RangeCheckAmount(64);
        destRC[d].v <== destLimbs[d];
    }

    component nullPose[nIns];
    for (var i4 = 0; i4 < nIns; i4++) {
        nullPose[i4] = Poseidon(2);
        nullPose[i4].inputs[0] <== receiverViewPriv;
        nullPose[i4].inputs[1] <== inSpendNonce[i4];
        nullPose[i4].out === inputNullifier[i4];
    }

    signal output pubMerkleRoot;
    pubMerkleRoot <== merkleRoot;

    signal output pubInputNullifier[nIns];
    for (var o0 = 0; o0 < nIns; o0++) {
        pubInputNullifier[o0] <== inputNullifier[o0];
    }

    signal output pubDestLimbs[4];
    for (var o1 = 0; o1 < 4; o1++) {
        pubDestLimbs[o1] <== destLimbs[o1];
    }

    signal output pubOutputCommitment[nOuts];
    for (var o2 = 0; o2 < nOuts; o2++) {
        pubOutputCommitment[o2] <== outputCommitment[o2];
    }

    signal output pubPublicAmount;
    pubPublicAmount <== publicAmount;

    signal output pubExtAmountIn;
    pubExtAmountIn <== extAmountIn;
}

component main = PrivateStealthJoinSplit(6, 6, 20);
