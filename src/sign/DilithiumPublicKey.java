package sign;

import java.security.PublicKey;

public class DilithiumPublicKey implements PublicKey {
	// private static final long serialVersionUID = 1L;
	private final byte[] rho;
	private final PolyVec t1;
	private final PolyVec[] A;
	private final byte[] pubbytes;

	public DilithiumPublicKey(byte[] rho, PolyVec t1, byte[] pubbytes, PolyVec[] A) {
		this.t1 = t1;
		this.rho = rho;
		this.pubbytes = pubbytes;
		this.A = A;
	}

	public String getAlgorithm() {
		return "Dilithium";
	}

	public String getFormat() {
		return "RAW";
	}

	public byte[] getEncoded() {
		return pubbytes;
	}

    public byte[] getRho() {
		return rho;
	}

	public PolyVec getT1() {
		return t1;
	}

	public PolyVec[] getA() {
		return A;
	}
}
