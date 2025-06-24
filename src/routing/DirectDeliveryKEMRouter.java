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

public class DirectDeliveryKEMRouter extends ActiveRouter {

    private KeyPair KemKeyPair;
    private KeyPair SignKeyPair;

    private Map<String, PublicKey> PublicKeys;
    private Map<String, Boolean> MyPublicKeySent;
    private Map<String, int[]> SharedSecrets;


    // Energy estimation
    private static final double ENC_ENERGY = 1.78;
    private static final double DEC_ENERGY = 0.83;
    private static final double SIGN_ENERGY = 6.745;
    private static final double VERIFY_ENERGY = 1.585;


    public DirectDeliveryKEMRouter(Settings s) {
        super(s);
    }

    protected DirectDeliveryKEMRouter(DirectDeliveryKEMRouter r) {
        super(r);
    }

    @Override
    public DirectDeliveryKEMRouter replicate() {
        return new DirectDeliveryKEMRouter(this);
    }
    
    @Override
    public void init(DTNHost host, List<MessageListener> mListeners) {
		super.init(host, mListeners);
        
        // Generate key pairs
        KemKeyPair = Kem.keygen();
        SignKeyPair = Dilithium.keygen(null);

        // Initialize maps
        MyPublicKeySent = new HashMap<>();
        PublicKeys = new HashMap<>();
        SharedSecrets = new HashMap<>();
    
    }

    @Override
    public void changedConnection(Connection c) {
        super.changedConnection(c);

        // Try to send public keys if the connection is up
        // and we haven't sent our public key to this peer yet.
        if (c.isUp()) {
            DTNHost peer = c.getOtherNode(getHost());
            if (MyPublicKeySent.containsKey(peer.toString())) return; // Already sent
            if (getHost().getAddress() < peer.getAddress()) {
                createNewMessage(createPublicKeyMsg(peer));
                MyPublicKeySent.put(peer.toString(), true);
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

        if (!getHost().equals(destination)) return m; // not for me

        if (id.startsWith("PublicKey")) {
            PublicKeys.put(m.getFrom().toString(), (PublicKey) m.getProperty("data"));
            createNewMessage(createEncryptedMessage(m));

        } else if (id.startsWith("CiphertextFrom")) {
            LogCiphertextReceive(m, origin, destination);
            receiveCiphertext(m);
        }

        return m;
    }

    private Message createPublicKeyMsg(DTNHost peer) {
        String msgId = "PublicKey" + getHost().toString();
        Message msg = new Message(getHost(), peer, msgId, KemKeyPair.getPublic().getEncoded().length);
        msg.addProperty("data", KemKeyPair.getPublic());
        return msg;
    }


    private void receiveCiphertext(Message m) {
        
        // Decrypt the message
        int[] ss = decrypt((CipherText) m.getProperty("data"),
                (KemPrivateKey) KemKeyPair.getPrivate(),
                (DilithiumPublicKey) (DilithiumPublicKey) m.getProperty("VerifyKey"),
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
        int [] sharedSecret = new int[Kem.N];
        Rng.sampleNoise(sharedSecret);
        
        // Encrypt the message
        KemPublicKey pk = (KemPublicKey) m.getProperty("data");
        CipherText ct = Kem.encapsulate(pk, sharedSecret);
        this.energy.reduceEnergy(ENC_ENERGY);
        // Sign the message
        byte[] sig = Dilithium.sign((DilithiumPrivateKey) SignKeyPair.getPrivate(), Utils.intArrayToByteArray(sharedSecret));
        this.energy.reduceEnergy(SIGN_ENERGY);
        // Store the shared secret
        SharedSecrets.put(origin.toString(), sharedSecret);
        
        // Create a new message with the ciphertext
        String msgId = "CiphertextFrom" + getHost().toString() + "To" + origin.toString();
        Message msg = new Message(getHost(), origin, msgId, ct.toString().length() + sig.length + SignKeyPair.getPublic().getEncoded().length);
        msg.addProperty("data", ct);
        msg.addProperty("signature", sig);
        msg.addProperty("VerifyKey", SignKeyPair.getPublic());
        return msg;
    }


    // Decrypt the ciphertext and verify the signature
    private int[] decrypt(CipherText ct, KemPrivateKey sk, DilithiumPublicKey vk, byte[] sig) {
        // Decrypt the ciphertext
        int[] sharedSecret = Kem.decapsulate(sk, ct);
        this.energy.reduceEnergy(DEC_ENERGY);
        // Verify the signature
        if (!Dilithium.verify(vk, sig, Utils.intArrayToByteArray(sharedSecret))) {
            System.out.println("Signature verification failed.");
            return null;
        }
        this.energy.reduceEnergy(VERIFY_ENERGY);
        return sharedSecret;
    }
   

    // Just for analysis purposes
    private boolean isSameSharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString())) return false;
        int[] mine = SharedSecrets.get(peer.toString());
        int[] their = ((DirectDeliveryKEMRouter) peer.getRouter()).sharedSecretWith(getHost());
        return Arrays.equals(mine, their);

    }

    // Just for analysis purposes
    private int[] sharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString())) return null;
        return SharedSecrets.get(peer.toString());
    }
}
