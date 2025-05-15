package kem;

import java.security.KeyPair;

public class Kem {
    
    public static final int N = 256;
    public static final int Q = 12289; // Modulus
    public static final int Q2 = Q / 2;
    public static final int Q4 = Q / 4;
    public static final int QINV = (1 << 24) / Q; // Precomputed value for Barrett reduction



    public static KeyPair keygen() {
        Poly a = new Poly();
        Rng.randomInt(a.getCoeffs());

        Poly r1, r2;
        r1 = new Poly();
        r2 = new Poly();
        Rng.sampleNoise(r1.getCoeffs());
        Rng.sampleNoise(r2.getCoeffs());

        Poly p = Poly.sub(r1, a.mult(r2));

        KemPublicKey pk = new KemPublicKey(a, p);
        KemPrivateKey sk = new KemPrivateKey(r2);
        return new KeyPair(pk, sk);
    }

    public static CipherText encapsulate(KemPublicKey pk, int[] m) {
        Poly a = pk.getA();
        Poly p = pk.getP();

        Poly mhat = new Poly(m);
        Poly e1, e2, e3;
        e1 = new Poly();
        e2 = new Poly();
        e3 = new Poly();
        Rng.sampleNoise(e1.getCoeffs());
        Rng.sampleNoise(e2.getCoeffs());
        Rng.sampleNoise(e3.getCoeffs());

        Poly c1 = Poly.add(Poly.mult(a, e1), e2);
        Poly c2 = Poly.add(Poly.mult(p, e1), e3.add(mhat));

        return new CipherText(c1, c2);
        
    }
    public static int[] decapsulate(KemPrivateKey sk, CipherText ct) {
        Poly r2 = sk.getR2();
        Poly c1 = ct.getC1();
        Poly c2 = ct.getC2();

        Poly mhat1 = Poly.mult(c1, r2).add(c2);

        return Utils.recon(mhat1);
    }
}
