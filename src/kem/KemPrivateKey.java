package kem;

import java.security.PrivateKey;

public class KemPrivateKey implements PrivateKey {
    
    private final Poly r2;

    public KemPrivateKey(Poly r2) {
        this.r2 = r2;
    }

    public String getAlgorithm() {
        return "Ring-BLWE";
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        return r2.toString().getBytes();
    }

    public Poly getR2() {
        return r2;
    }
}
