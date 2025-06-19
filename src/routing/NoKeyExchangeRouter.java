package routing;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import core.Connection;
import core.DTNHost;
import core.Message;
import core.MessageListener;
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

public class NoKeyExchangeRouter extends ActiveRouter {

    private KeyPair KemKeyPair;
    private KeyPair SignKeyPair;

    private Map<String, PublicKey> PublicKeys;
    private Map<String, Boolean> MyPublicKeySent;
    private Map<String, int[]> SharedSecrets;
    private Map<String, Message> Ciphertexts;



    public NoKeyExchangeRouter(Settings s) {
        super(s);
    }

    protected NoKeyExchangeRouter(NoKeyExchangeRouter r) {
        super(r);
    }

    @Override
    public NoKeyExchangeRouter replicate() {
        return new NoKeyExchangeRouter(this);
    }

    @Override
    public void init(DTNHost host, List<MessageListener> mListeners) {
        super.init(host, mListeners);

        // Generate key pairs
        KemKeyPair = Kem.keygen();
        SignKeyPair = Dilithium.keygen(null);
        // this.energy.reduce(KEY_GEN_ENERGY);

        // Initialize maps
        MyPublicKeySent = new HashMap<>();
        PublicKeys = new HashMap<>();
        SharedSecrets = new HashMap<>();
        Ciphertexts = new HashMap<>();

    }

    @Override
    public void changedConnection(Connection c) {
        super.changedConnection(c);

        // Try to send public keys if the connection is up
        // and we haven't sent our public key to this peer yet.
        if (c.isUp()) {
            DTNHost peer = c.getOtherNode(getHost());
            if (MyPublicKeySent.containsKey(peer.toString()))
                return; // Already sent
            if (getHost().getAddress() > peer.getAddress()) {
                createNewMessage(createVerifyPublicKeyMsg(peer));
            } else {
                createNewMessage(createKemPublicKeyMsg(peer));
            }
        }
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

    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {

        Message m = super.messageTransferred(id, from);

        DTNHost origin = m.getFrom();
        DTNHost destination = m.getTo();

        if (!getHost().equals(destination))
            return m; // not for me

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

    private void receivePublicKey(Message m, String type) {

        PublicKeys.put(m.getFrom().toString(), (PublicKey) m.getProperty("data"));
        ((NoKeyExchangeRouter) m.getFrom().getRouter()).ACK_PUBKEY(getHost());

        switch (type) {
            case "VerifyPubKey":
                // // Try to decrypt again only a ciphertext was saved.
                // if (!Ciphertexts.containsKey(m.getFrom().toString()))
                //     return;
                // int[] ss = decrypt((CipherText) Ciphertexts.get(m.getFrom().toString()).getProperty("data"),
                //         (KemPrivateKey) KemKeyPair.getPrivate(),
                //         (DilithiumPublicKey) PublicKeys.get(m.getFrom().toString()),
                //         (byte[]) Ciphertexts.get(m.getFrom().toString()).getProperty("signature"));
                // // Store the shared secret
                // SharedSecrets.put(m.getFrom().toString(), ss);
                // // Check if the shared secret is the same as the one we generated
                // if (isSameSharedSecretWith(m.getFrom())) {
                //     LogKeyExchangeSuccess(m.getTo(), m.getFrom());
                // } else {
                //     LogKeyExchangeFailure(m.getTo(), m.getFrom());
                // }
                break;
            case "KemPubKey":
                // Encrypt the message
                createNewMessage(createEncryptedMessage(m));
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
        } else {
            LogKeyExchangeFailure(m.getTo(), m.getFrom());
        }
    }

    private Message createEncryptedMessage(Message m) {
        DTNHost origin = m.getFrom();

        // Generate a shared secret
        int[] sharedSecret = new int[Kem.N];
        Rng.sampleNoise(sharedSecret);

        // Encrypt the message
        KemPublicKey pk = (KemPublicKey) m.getProperty("data");
        CipherText ct = Kem.encapsulate(pk, sharedSecret);
        // this.energy.reduceEnergy(ENC_DEC_ENERGY);
        // Sign the message
        byte[] sig = Dilithium.sign((DilithiumPrivateKey) SignKeyPair.getPrivate(),
                Utils.intArrayToByteArray(sharedSecret));
        // this.energy.reduceEnergy(SIGN_VERIFY_ENERGY);
        // Store the shared secret
        SharedSecrets.put(origin.toString(), sharedSecret);

        // Create a new message with the ciphertext
        String msgId = "CiphertextFrom" + getHost().toString();
        Message msg = new Message(getHost(), origin, msgId, ct.toString().length());
        msg.addProperty("data", ct);
        msg.addProperty("signature", sig);
        return msg;
    }

    // Decrypt the ciphertext and verify the signature
    private int[] decrypt(CipherText ct, KemPrivateKey sk, DilithiumPublicKey vk, byte[] sig) {
        // Decrypt the ciphertext
        int[] sharedSecret = Kem.decapsulate(sk, ct);
        // this.energy.reduceEnergy(ENC_DEC_ENERGY);
        // Verify the signature
        if (!Dilithium.verify(vk, sig, Utils.intArrayToByteArray(sharedSecret))) {
            System.out.println("Signature verification failed.");
            return null;
        }
        // this.energy.reduceEnergy(SIGN_VERIFY_ENERGY);
        return sharedSecret;
    }

    private void ACK_PUBKEY(DTNHost peer) {
        // Send an ACK message to the peer
        MyPublicKeySent.put(peer.toString(), true);
    }

    // Just for testing purposes
    private boolean isSameSharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString()))
            return false;
        int[] mine = SharedSecrets.get(peer.toString());
        int[] their = ((NoKeyExchangeRouter) peer.getRouter()).sharedSecretWith(getHost());
        return Arrays.equals(mine, their);

    }

    // Just for testing purposes
    private int[] sharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString()))
            return null;
        return SharedSecrets.get(peer.toString());
    }
}
