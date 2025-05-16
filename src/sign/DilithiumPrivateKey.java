package sign;

import java.security.PrivateKey;

public class DilithiumPrivateKey implements PrivateKey {

    private final byte[] rho;
    private final byte[] tr;
    private final byte[] K;
    private final PolyVec s1;
    private final PolyVec s2;
    private final PolyVec t0;
    private final PolyVec s1Hat;
    private final PolyVec s2Hat;
    private final PolyVec t0Hat;
    private final byte[] prvbytes;
    private final PolyVec[] A;

    public DilithiumPrivateKey(byte[] rho, byte[] K, byte[] tr, PolyVec s1, PolyVec s2, PolyVec t0, byte[] prvbytes, PolyVec[] A, PolyVec s1Hat, PolyVec s2Hat, PolyVec t0Hat) {
		this.rho = rho;
		this.tr = tr;
		this.K = K;
		this.s1 = s1;
		this.s2 = s2;
		this.t0 = t0;
		this.prvbytes = prvbytes;
		this.A = A;
		this.s1Hat = s1Hat;
		this.s2Hat = s2Hat;
		this.t0Hat = t0Hat;
	}

    public String getAlgorithm() {
        return "Dilithium";
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        return prvbytes;
    }
    public byte[] getRho() {
        return rho;
    }
    public byte[] getTr() {
        return tr;
    }

    public byte[] getK() {
        return K;
    }

    public PolyVec getS1() {
        return s1;
    }

    public PolyVec getS2() {
        return s2;
    }

    public PolyVec getT0() {
        return t0;
    }

    public PolyVec[] getA() {
        return A;
    }

    public PolyVec getS1Hat() {
        return s1Hat;
    }

    public PolyVec getS2Hat() {
        return s2Hat;
    }

    public PolyVec getT0Hat() {
        return t0Hat;
    }
}