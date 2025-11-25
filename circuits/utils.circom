pragma circom 2.0.0;

include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/comparators.circom";

template PackU64x4Safe2() {
    signal input limbs[4];
    signal output out[2];

    component limbBits[4];
    for (var i = 0; i < 4; i++) {
        limbBits[i] = Num2Bits(64);
        limbBits[i].in <== limbs[i];
    }

    var TWO64 = 18446744073709551616;

    out[0] <== limbs[0] + limbs[1] * TWO64;
    out[1] <== limbs[2] + limbs[3] * TWO64;
}

template Add2() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b;
}

template SumN(n) {
    signal input in[n];
    signal output out;

    if (n == 0) {
        out <== 0;
    } else if (n == 1) {
        out <== in[0];
    } else {
        component adders[n-1];

        adders[0] = Add2();
        adders[0].a <== in[0];
        adders[0].b <== in[1];

        for (var i = 2; i < n; i++) {
            adders[i-1] = Add2();
            adders[i-1].a <== adders[i-2].out;
            adders[i-1].b <== in[i];
        }

        out <== adders[n-2].out;
    }
}

template RangeCheckAmount(bits) {
    signal input v;
    component b = Num2Bits(bits);
    b.in <== v;
}
