package kem;

import java.security.SecureRandom;


public class Rng {
    
    public static void randomInt(int[] coeffs) {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < coeffs.length; i++) {
            coeffs[i] = random.nextInt(Kem.Q);
        }
    }

    public static void sampleNoise(int[] coeffs) {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < coeffs.length; i++) {
            coeffs[i] = random.nextInt(2);
        }
    }



}
