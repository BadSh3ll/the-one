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

import kem.Kem;
import kem.KemPrivateKey;
import kem.KemPublicKey;
import kem.CipherText;
import kem.Rng;
import kem.Utils;

import sign.Dilithium;
import sign.DilithiumPrivateKey;
import sign.DilithiumPublicKey;

public class KeyExchangeRouter extends ActiveRouter {

    private static int count = 0;
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
        this.Ciphertexts = new HashMap<>();
    }


    @Override
    public void update() {

        createPublicKeyMsg();
        super.update();

        if (isTransferring() || !canStartTransfer()) {
            return; // transferring, don't try other connections yet
        }

        // Try first the messages that can be delivered to final recipient
        if (exchangeDeliverableMessages() != null) {
            return; // started a transfer, don't try others (yet)
        }
        // Send public key to all connections
    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {

        Message m = super.messageTransferred(id, from);

        DTNHost origin = m.getFrom();
        DTNHost destination = m.getTo();

        if (!getHost().equals(destination)) return m; // not for me

        if (id.startsWith("VerifyPubKey")) {
            LogPublicKeyReceive(m, origin, destination);
            receivePublicKey(m, "VerifyPubKey");

        } else if (id.startsWith("KemPubKey")) {
            LogPublicKeyReceive(m, origin, destination);
            receivePublicKey(m, "KemPubKey");

        } else if (id.startsWith("CiphertextFrom")) {
            LogCiphertextReceive(m, origin, destination);
            receiveCiphertext(m);
        }

        return m;
    }

    @Override
    public KeyExchangeRouter replicate() {
        return new KeyExchangeRouter(this);
    }

    private Message createVerifyPublicKeyMsg(DTNHost peer) {
        String msgId = "VerifyPubKey" + getHost().toString();
        Message msg = new Message(getHost(), peer, msgId, SignKeyPair.getPublic().getEncoded().length);
        msg.addProperty("data", SignKeyPair.getPublic());
        return msg;
    }
    private Message createKemPublicKeyMsg(DTNHost peer) {
        String msgId = "KemPubKey" + getHost().toString();
        Message msg = new Message(getHost(), peer, msgId, KemKeyPair.getPublic().getEncoded().length);
        msg.addProperty("data", KemKeyPair.getPublic());
        return msg;
    }

    private void createPublicKeyMsg() {
        for (Connection c : getConnections()) {
            DTNHost peer = c.getOtherNode(getHost());
            Message msg = null;
            if (MyPublicKeySent.containsKey(peer.toString())) continue; // Already sent
            if (getHost().toString().compareTo(peer.toString()) >  0) {
                msg = createVerifyPublicKeyMsg(peer);
            } else {
                msg = createKemPublicKeyMsg(peer);
            }
            // MyPublicKeySent.put(peer.toString(), true);
            createNewMessage(msg);
        }
    }


    private void receivePublicKey(Message m, String type) {

        PublicKeys.put(m.getFrom().toString(), (PublicKey) m.getProperty("data"));
        ((KeyExchangeRouter) m.getFrom().getRouter()).ACK_PUBKEY(getHost());

        switch (type) {
            case "VerifyPubKey":
                // Try to decrypt again only a ciphertext was saved.
                if (!Ciphertexts.containsKey(m.getFrom().toString())) return;
                int[] ss = decrypt((CipherText) Ciphertexts.get(m.getFrom().toString()).getProperty("data"),
                        (KemPrivateKey) KemKeyPair.getPrivate(),
                        (DilithiumPublicKey) PublicKeys.get(m.getFrom().toString()),
                        (byte[]) Ciphertexts.get(m.getFrom().toString()).getProperty("signature"));
                // Store the shared secret
                SharedSecrets.put(m.getFrom().toString(), ss);
                // Check if the shared secret is the same as the one we generated
                if (isSameSharedSecretWith(m.getFrom())) {
                    LogKeyExchangeSuccess(m.getTo(), m.getFrom());
                    System.out.println(++count);
                } else {
                    LogKeyExchangeFailure(m.getTo(), m.getFrom());
                }
                break;
            case "KemPubKey":
                // Encrypt the message
                createEncryptedMessage(m);
                break;
            default:
                System.out.println("Unknown public key type received.");
        }

    }

    private void receiveCiphertext(Message m) {
        if (!PublicKeys.containsKey(m.getFrom().toString())) {
            Ciphertexts.put(m.getFrom().toString(), m);
            return;
        }
        // Decrypt the message
        int[] ss = decrypt((CipherText) m.getProperty("data"),
                (KemPrivateKey) KemKeyPair.getPrivate(),
                (DilithiumPublicKey) PublicKeys.get(m.getFrom().toString()),
                (byte[]) m.getProperty("signature"));
        // Store the shared secret
        SharedSecrets.put(m.getFrom().toString(), ss);
        // Check if the shared secret is the same as the one we generated
        if (isSameSharedSecretWith(m.getFrom())) {
            LogKeyExchangeSuccess(m.getTo(), m.getFrom());
            System.out.println(++count);
        } else {
            LogKeyExchangeFailure(m.getTo(), m.getFrom());
        }
    }

    private Message createEncryptedMessage(Message m) {
        DTNHost origin = m.getFrom();
        // Generate a shared secret
        int [] sharedSecret = new int[Kem.N];
        Rng.sampleNoise(sharedSecret);
        // Encrypt the message
        KemPublicKey pk = (KemPublicKey) m.getProperty("data");
        CipherText ct = Kem.encapsulate(pk, sharedSecret);
        // Sign the message
        byte[] sig = Dilithium.sign((DilithiumPrivateKey) SignKeyPair.getPrivate(), intArrayToByteArray(sharedSecret));
        // Store the shared secret
        SharedSecrets.put(origin.toString(), sharedSecret);
        // Create a new message with the ciphertext
        String msgId = "CiphertextFrom" + getHost().toString();
        Message msg = new Message(getHost(), origin, msgId, ct.toString().length());
        msg.addProperty("data", ct);
        msg.addProperty("signature", sig);
        createNewMessage(msg);
        return msg;
    }


    // Decrypt the ciphertext and verify the signature
    private int[] decrypt(CipherText ct, KemPrivateKey sk, DilithiumPublicKey vk, byte[] sig) {
        // Decrypt the ciphertext
        int[] sharedSecret = Kem.decapsulate(sk, ct);
        // Verify the signature
        if (!Dilithium.verify(vk, sig, intArrayToByteArray(sharedSecret))) {
            System.out.println("Signature verification failed.");
            return null;
        }
        return sharedSecret;
    }
    public static byte[] intArrayToByteArray(int[] arr) {
        byte[] out = new byte[arr.length * 4];
        for (int i = 0; i < arr.length; i++) {
            out[i * 4]     = (byte) ((arr[i] >> 24) & 0xFF);
            out[i * 4 + 1] = (byte) ((arr[i] >> 16) & 0xFF);
            out[i * 4 + 2] = (byte) ((arr[i] >> 8) & 0xFF);
            out[i * 4 + 3] = (byte) (arr[i] & 0xFF);
        }
        return out;
    }

    private void ACK_PUBKEY(DTNHost peer) {
        // Send an ACK message to the peer
        MyPublicKeySent.put(peer.toString(), true);
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
