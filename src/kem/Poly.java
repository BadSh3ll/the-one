package kem;


public class Poly {

    private int[] coeffs;


    public Poly() {
        this.coeffs = new int[Kem.N]; // Example size
    }

    public Poly(int[] coeffs) {
        this.coeffs = new int[Kem.N];
        for (int i = 0; i < Kem.N; i++) {
            this.coeffs[i] = coeffs[i] == 1 ? Kem.Q2 : 0;
        }
    }


    public int[] getCoeffs() {
        return coeffs;
    }

    public int get(int index) {
        return coeffs[index];
    }


    // Add two polynomials
    public static Poly add(Poly a, Poly b) {
        Poly result = new Poly();
        for (int i = 0; i < Kem.N; i++) {
            result.coeffs[i] = reduce(a.coeffs[i] + b.coeffs[i]);
        }
        return result;
    }

    public Poly add(Poly b) {
        return add(this, b);
    }


    // Subtract two polynomials
    public static Poly sub(Poly a, Poly b) {
        Poly result = new Poly();
        for (int i = 0; i < Kem.N; i++) {
            result.coeffs[i] = reduce(a.coeffs[i] - b.coeffs[i]);
        }
        return result;
    }
    public Poly sub(Poly b) {
        return sub(this, b);
    }


    // Multiply two polynomials
    public static Poly mult(Poly a, Poly b) {
        Poly result = new Poly();
        for (int i = 0; i < Kem.N; i++) {
            if (b.coeffs[i] == 0) continue;
            for (int j = 0; j < Kem.N; j++) {
                int k = (i + j) >= Kem.N ? (i + j - Kem.N) : (i + j);
                int sign = ((i + j) >= Kem.N) ? -1 : 1;
                result.coeffs[k] = reduce(result.coeffs[k] + sign * a.coeffs[j]);
            }
        }
        return result;
    }
    
    public Poly mult(Poly b) {
        return mult(this, b);
    }

    public static int reduce(int x) {
        int t = (x * Kem.QINV) >> 24;
        int result = x - t * Kem.Q;   

        if (result < 0) {
            result += Kem.Q;
        } else if (result >= Kem.Q) {
            result -= Kem.Q;
        }
        return result;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < coeffs.length; i++) {
            sb.append("" + coeffs[i]);
        }
        return sb.toString();
    }


}
