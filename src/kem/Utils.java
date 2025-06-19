package kem;

public class Utils {
    

    public static void printPoly(Poly poly) {
        System.out.println(poly.toString());
    }


    public static int[] recon(Poly mhat) {
        int[] m = new int[Kem.N];
        for (int i = 0; i < Kem.N; i++) {
            m[i] = Math.abs(mhat.get(i) - Kem.Q2) <= Kem.Q4 ? 1 : 0;
        }
        return m;
    }

    public static void printMsg(int[] msg) {
        for (int i = 0; i < msg.length; i++) {
            System.out.print(msg[i] + " ");
        }
        System.out.println();
    }

    public static byte[] intArrayToByteArray(int[] arr) {
        byte[] out = new byte[arr.length * 4];
        for (int i = 0; i < arr.length; i++) {
            out[i * 4] = (byte) ((arr[i] >> 24) & 0xFF);
            out[i * 4 + 1] = (byte) ((arr[i] >> 16) & 0xFF);
            out[i * 4 + 2] = (byte) ((arr[i] >> 8) & 0xFF);
            out[i * 4 + 3] = (byte) (arr[i] & 0xFF);
        }
        return out;
    }
}
