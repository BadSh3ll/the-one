package kem;

import java.security.PublicKey;

public class KemPublicKey implements PublicKey {
    
    private final Poly a;
    private final Poly p;

    public KemPublicKey(Poly a, Poly p) {
        this.a = a;
        this.p = p;
    }


    public String getAlgorithm() {
        return "Ring-BLWE";
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        return (a.toString() + p.toString()).getBytes();
    }

    public Poly getA() {
        return a;
    }
    public Poly getP() {
        return p;
    }
}
