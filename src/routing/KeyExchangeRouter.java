package routing;

import java.security.KeyPair;
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

public class KeyExchangeRouter extends ActiveRouter {
    
    static int keyExchangedCount = 0;

    private KeyPair keyPair;

    private Map<String, KemPublicKey> PublicKeys = new HashMap<>();
    private Map<String, Boolean> MyPublicKeySent = new HashMap<>();
    private Map<String, int[]> SharedSecrets = new HashMap<>();


    public KeyExchangeRouter(Settings s) {
        super(s);
    }

    /**
     * Copy constructor.
     * @param r The router prototype where setting values are copied from
     */
    protected KeyExchangeRouter(KeyExchangeRouter r) {
        super(r);
        this.keyPair = Kem.keygen();
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

        if (m.getId().startsWith("KemPubKey")) {
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
            // Only send public key if this host's ID is smaller (Alice)
            if (getHost().toString().compareTo(peer.toString()) < 0) {
                if (!MyPublicKeySent.containsKey(peer.toString())) {
                    String msgId = "KemPubKey" + getHost().toString();
                    Message msg = new Message(getHost(), peer, msgId, keyPair.getPublic().getEncoded().length);
                    msg.addProperty("data", keyPair.getPublic());
                    createNewMessage(msg);
                    MyPublicKeySent.put(peer.toString(), true);
                }
            }
        }
    }

    private void receivePublicKey(Message m) {


        DTNHost origin = m.getFrom();
        if (origin.toString().compareTo(getHost().toString()) > 0) return; // Only accept if this host's ID is smaller (Bob)
        if (PublicKeys.containsKey(origin.toString()) || origin.equals(getHost())) return; // Already received or it is my own key

        // Public key received
        LogPublicKeyReceive(m, origin, getHost()); // Log the public key reception
        KemPublicKey pubKey = (KemPublicKey) m.getProperty("data");
        PublicKeys.put(origin.toString(), pubKey);
    

        int[] sharedSecret = new int[Kem.N];
        Rng.sampleNoise(sharedSecret);
        System.out.println("Shared secret encrypted: ");
        Utils.printMsg(sharedSecret);
        SharedSecrets.put(origin.toString(), sharedSecret);
        CipherText ct = Kem.encapsulate(pubKey, sharedSecret);
    
        // Send encapsulated key to origin
        String msgId = "CiphertextFrom" + getHost().toString();
        Message msg = new Message(getHost(), origin, msgId, ct.toString().length());
        msg.addProperty("data", ct);

        createNewMessage(msg);
        
        tryAllMessagesToAllConnections();
    }

    private void receiveCiphertext(Message m) {

        DTNHost origin = m.getFrom();
        DTNHost destination = m.getTo();
        if (!destination.equals(getHost())) return; // Not for me
        
        if (SharedSecrets.containsKey(origin.toString())) return; // Already received

        // Ciphertext received
        LogCiphertextReceive(m, origin, destination);


        // Decrypt the ciphertext
        CipherText ct = (CipherText) m.getProperty("data");
        int[] sharedSecret = Kem.decapsulate((KemPrivateKey)keyPair.getPrivate(), ct);

        System.out.println("Shared secret decrypted: ");
        Utils.printMsg(sharedSecret);
        
        
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
