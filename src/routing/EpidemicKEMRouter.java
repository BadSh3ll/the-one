package routing;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import core.Connection;
import core.DTNHost;
import core.Message;
import core.MessageListener;
import core.Settings;
import core.SimScenario;
import kem.CipherText;
import kem.Kem;
import kem.KemPrivateKey;
import kem.KemPublicKey;
import kem.Rng;
import kem.Utils;
import sign.Dilithium;
import sign.DilithiumPrivateKey;
import sign.DilithiumPublicKey;

public class EpidemicKEMRouter extends ActiveRouter {


    private KeyPair KemKeyPair;
    private KeyPair SignKeyPair;

    private Map<String, KemPublicKey> PublicKeys;
    private Map<String, int[]> SharedSecrets;
    //
    private static final double ENC_ENERGY = 1.78;
    private static final double DEC_ENERGY = 0.83;
    private static final double SIGN_ENERGY = 6.745;
    private static final double VERIFY_ENERGY = 1.585;


    public EpidemicKEMRouter(Settings s) {
        super(s);
    }

    protected EpidemicKEMRouter(EpidemicKEMRouter r) {
        super(r);
    }

    @Override
    public EpidemicKEMRouter replicate() {
        return new EpidemicKEMRouter(this);
    }

    @Override
    public void init(DTNHost host, List<MessageListener> mListeners) {
        super.init(host, mListeners);

        KemKeyPair = Kem.keygen();
        SignKeyPair = Dilithium.keygen(null);

        PublicKeys = new HashMap<>();
        SharedSecrets = new HashMap<>();

        PublicKeys.put(getHost().toString(), (KemPublicKey) KemKeyPair.getPublic());
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

        this.tryAllMessagesToAllConnections(); // Try to send messages to all connections

    }


    @Override
    public void changedConnection(Connection c) {
        super.changedConnection(c);

        // Try to share public keys if the connection is up
        if (c.isUp()) {
            DTNHost peer = c.getOtherNode(getHost());
            shareKeys(peer);
        }
    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {

        Message m = super.messageTransferred(id, from);

        // If the message is a public key or verify key, add it to the respective map
        if (m.getId().startsWith("PublicKey") && !PublicKeys.containsKey((String) m.getProperty("hostId"))) {
            KemPublicKey publicKey = (KemPublicKey) m.getProperty("data");
            PublicKeys.put((String) m.getProperty("hostId"), publicKey);

            if (getHost().toString().compareTo((String) m.getProperty("hostId")) > 0) {
                createNewMessage(createCipherTextMessage(m));
            }
        } else if (m.getId().startsWith("CiphertextFrom") && m.getTo().equals(getHost())) {

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
        
        return m;

    }



    public void shareKeys(DTNHost peer) {

        Set<String> missingPublicKeys = missingKeys(PublicKeys.keySet(), ((EpidemicKEMRouter) peer.getRouter()).getKnownPublicKeys());

        if (missingPublicKeys.isEmpty()) {
            return; // No keys to share
        }

        for (String hostId : missingPublicKeys) {
            KemPublicKey publicKey = PublicKeys.get(hostId);
            String msgId = "PublicKey" + hostId;
            Message message = new Message(getHost(), peer, msgId, 2096);
            message.addProperty("hostId",  hostId);
            message.addProperty("data", publicKey);
            createNewMessage(message);
        }
    }

    public Set<String> missingKeys(Set<String> mines,  Set<String> theirs) {

        Set<String> missing = new HashSet<>();

        for (String mine: mines) {
            if (theirs.contains(mine)) continue;
            missing.add(mine);
        }
        return missing;

    }

    public Set<String> getKnownPublicKeys() {
        return PublicKeys.keySet();
    }

    public Message createCipherTextMessage(Message pkmsg) {

        String hostId = (String) pkmsg.getProperty("hostId");
        DTNHost peer = SimScenario.getInstance().getWorld().getNodeByAddress(Integer.parseInt(hostId.substring(1)));

        KemPublicKey publicKey = (KemPublicKey) pkmsg.getProperty("data");


        int [] sharedSecret = new int[Kem.N];
        Rng.sampleNoise(sharedSecret);

        CipherText ct = Kem.encapsulate(publicKey, sharedSecret);
        this.energy.reduceEnergy(ENC_ENERGY);
        // Sign the message
        byte[] sig = Dilithium.sign((DilithiumPrivateKey) SignKeyPair.getPrivate(), Utils.intArrayToByteArray(sharedSecret));
        this.energy.reduceEnergy(SIGN_ENERGY);
        // Store the shared secret
        SharedSecrets.put(peer.toString(), sharedSecret);

        // Create a new message with the ciphertext
        String msgId = "CiphertextFrom" + getHost().toString() + "To" + hostId;
        Message msg = new Message(getHost(), peer, msgId, 2000);
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
        int[] their = ((EpidemicKEMRouter) peer.getRouter()).sharedSecretWith(getHost());
        return Arrays.equals(mine, their);

    }

    // Just for analysis purposes
    private int[] sharedSecretWith(DTNHost peer) {
        if (!SharedSecrets.containsKey(peer.toString())) return null;
        return SharedSecrets.get(peer.toString());
    }

}
