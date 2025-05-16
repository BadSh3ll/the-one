package routing;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


import core.Connection;
import core.DTNHost;
import core.Message;
import core.Settings;

import kem.CipherText;
import kem.Kem;
import kem.KemPrivateKey;
import kem.KemPublicKey;
import kem.Rng;
import kem.Utils;

import sign.Dilithium;
import sign.DilithiumPrivateKey;
import sign.DilithiumPublicKey;

public class KeyExchangeRouter extends ActiveRouter {

    static int keyExchangedCount = 0;

    private KeyPair KemKeyPair;
    private KeyPair SignKeyPair;

    private Map<String, PublicKey> PublicKeys = new HashMap<>();
    private Map<String, Boolean> MyPublicKeySent = new HashMap<>();
    private Map<String, int[]> SharedSecrets = new HashMap<>();
    private Map<String, Message> Ciphertexts = new HashMap<>();


    public KeyExchangeRouter(Settings s) {
        super(s);
    }

    /**
     * Copy constructor.
     * @param r The router prototype where setting values are copied from
     */
    protected KeyExchangeRouter(KeyExchangeRouter r) {
        super(r);
        this.KemKeyPair = Kem.keygen();
        this.SignKeyPair = Dilithium.keygen(null);

        this.MyPublicKeySent = new HashMap<>();
        this.PublicKeys = new HashMap<>();
        this.SharedSecrets = new HashMap<>();
    }


    @Override
    public void update() {

        super.update();

        if (isTransferring() || !canStartTransfer()) {
            return; // transferring, don't try other connections yet
        }

        // Try first the messages that can be delivered to final recipient
        if (exchangeDeliverableMessages() != null) {
            return; // started a transfer, don't try others (yet)
        }

        // Send public key to all connections
        sentPublicKey();


        this.tryAllMessagesToAllConnections();
    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {

        Message m = super.messageTransferred(id, from);

        if (m.getId().startsWith("KemPubKey") || m.getId().startsWith("VerifyPubKey")) {
            receivePublicKey(m);
        } else if (m.getId().startsWith("CiphertextFrom")) {
            receiveCiphertext(m);
        }

        return m;
    }

    @Override
    public KeyExchangeRouter replicate() {
        return new KeyExchangeRouter(this);
    }

    public void printMessageInfo(Message m) {
        System.out.println("_______________________________________");
        System.out.println("Time:" + String.format("%.2f", m.getReceiveTime()));
        System.out.println("Id: " + m.getId());
        System.out.println("From: " + m.getFrom().toString());
        System.out.println("To: " + m.getTo().toString());
        System.out.println("_______________________________________");
    }


    private void sentPublicKey() {
        for (Connection c : getConnections()) {
            DTNHost peer = c.getOtherNode(getHost());
            if (MyPublicKeySent.containsKey(peer.toString())) return;

            // Send the KEM public key if this host's ID is smaller (Alice)
            if (getHost().toString().compareTo(peer.toString()) < 0) {
                String msgId = "KemPubKey" + getHost().toString();
                Message msg = new Message(getHost(), peer, msgId, KemKeyPair.getPublic().getEncoded().length);
                msg.addProperty("data", KemKeyPair.getPublic());
                createNewMessage(msg);
                MyPublicKeySent.put(peer.toString(), true);
            } else {
            // If this host's ID is greater (Bob), send the other (Alice) the sinature public key
                String msgId = "VerifyPubKey" + getHost().toString();
                Message msg = new Message(getHost(), peer, msgId, SignKeyPair.getPublic().getEncoded().length);
                msg.addProperty("data", SignKeyPair.getPublic());
                createNewMessage(msg);
                MyPublicKeySent.put(peer.toString(), true);
            }
        }
    }

    private void receivePublicKey(Message m) {


        DTNHost origin = m.getFrom();

        if (PublicKeys.containsKey(origin.toString()) || origin.equals(getHost())) return; // Already received or it is my own key

        LogPublicKeyReceive(m, origin, getHost()); // Log the public key reception
        // Get the Public key
        PublicKey pubKey = (PublicKey) m.getProperty("data");
        PublicKeys.put(origin.toString(), pubKey);

        // If this host's ID is larger (Bob), encrypt and sign the shared secret
        if (origin.toString().compareTo(getHost().toString()) < 0) {

            int[] sharedSecret = new int[Kem.N];
            Rng.sampleNoise(sharedSecret);
            System.out.println("Shared secret encrypted: ");
            Utils.printMsg(sharedSecret);
            SharedSecrets.put(origin.toString(), sharedSecret);
            CipherText ct = Kem.encapsulate((KemPublicKey) pubKey, sharedSecret);

            byte[] sig = Dilithium.sign((DilithiumPrivateKey) SignKeyPair.getPrivate(), sharedSecret.toString().getBytes());

            System.out.println("Signature created: ");
            for (int i = 0; i < sig.length; i++) {
                System.out.print(sig[i] + " ");
            }
            System.out.println();

            // Send encapsulated key to origin
            String msgId = "CiphertextFrom" + getHost().toString();
            Message msg = new Message(getHost(), origin, msgId, ct.toString().length());
            msg.addProperty("data", ct);
            msg.addProperty("sig", sig);

            createNewMessage(msg);
        } else {
            // If this host's ID is smaller (Alice),
            // Try to decrypt if last attempt was unsuccessful
            if (Ciphertexts.containsKey(origin.toString())) {
                Message m2 = Ciphertexts.get(origin.toString());
                CipherText ct = (CipherText) m2.getProperty("data");
                byte[] sig = (byte[]) m2.getProperty("sig");
                int[] sharedSecret = decapsulate(ct, (KemPrivateKey) KemKeyPair.getPrivate(), (DilithiumPublicKey) PublicKeys.get(origin.toString()), sig);
                if (sharedSecret != null) {
                    SharedSecrets.put(origin.toString(), sharedSecret);
                    LogKeyExchangeSuccess(origin, getHost());
                } else {
                    LogKeyExchangeFailure(origin, getHost());
                }
            }
        }
        tryAllMessagesToAllConnections();
    }

    private void receiveCiphertext(Message m) {

        DTNHost origin = m.getFrom();
        DTNHost destination = m.getTo();
        if (!destination.equals(getHost())) return; // Not for me

        if (SharedSecrets.containsKey(origin.toString())) return; // Already received

        // Ciphertext received
        LogCiphertextReceive(m, origin, destination);



        if (!PublicKeys.containsKey(origin.toString())) {
            Ciphertexts.put(origin.toString(), m);
            System.out.println("No VerifyPubKey of " + origin.toString() + " received yet"); // Try later when the key is received
            return;
        }
        // Get the public key
        DilithiumPublicKey pubKey = (DilithiumPublicKey) PublicKeys.get(origin.toString());
        // Decrypt the ciphertext
        CipherText ct = (CipherText) m.getProperty("data");
        byte[] sig = (byte[]) m.getProperty("sig");
        int[] sharedSecret = decapsulate(ct, (KemPrivateKey) KemKeyPair.getPrivate(), (DilithiumPublicKey) pubKey, sig);
        if (sharedSecret == null) {
            System.out.println("Decryption failed");
            return;
        }



        // Store the shared secret
        SharedSecrets.put(origin.toString(), sharedSecret);

        // Check if the shared secret is the same with the origin
        // If it is, we successfully exchanged keys
        // If not, we failed to exchange keys
        if (isSameSharedSecretWith(origin)) {
            LogKeyExchangeSuccess(origin, destination);
        } else {
            LogKeyExchangeFailure(origin, destination);
        }


    }


    private int[] decapsulate(CipherText ct, KemPrivateKey sk, DilithiumPublicKey VerifyPubKey, byte[] sig) {

        System.out.println("Signature received: ");
        for (int i = 0; i < sig.length; i++) {
            System.out.print(sig[i] + " ");
        }
        System.out.println();
        // Decrypt the ciphertext
        int[] sharedSecret = Kem.decapsulate(sk, ct);
        System.out.println("Shared secret decrypted: ");
        Utils.printMsg(sharedSecret);
        // Verify the signature
        boolean valid = Dilithium.verify(VerifyPubKey, sig, sharedSecret.toString().getBytes());
        if (!valid) {
            System.out.println("Signature verification failed");
            return null;
        }
        return sharedSecret;
    }

    // Just for testing purposes
    private boolean isSameSharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString())) return false;
        int[] mine = SharedSecrets.get(peer.toString());
        int[] their = ((KeyExchangeRouter) peer.getRouter()).sharedSecretWith(getHost());
        return Arrays.equals(mine, their);

    }

    // Just for testing purposes
    private int[] sharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString())) return null;
        return SharedSecrets.get(peer.toString());
    }
}
