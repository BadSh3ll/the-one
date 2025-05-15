package kem;

public class CipherText {
    private final Poly c1;
    private final Poly c2;

    public CipherText(Poly c1, Poly c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public Poly getC1() {
        return c1;
    }

    public Poly getC2() {
        return c2;
    }

    @Override
    public String toString() {
        return c1.toString() + c2.toString();
    }
}
