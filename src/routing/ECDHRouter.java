package routing;

import java.util.*;

import core.Connection;
import core.DTNHost;
import core.Message;
import core.MessageListener;
import core.Settings;

public class ECDHRouter extends ActiveRouter {

    private static final double SHARED_SECRET_ENERGY = 57.12;

    // Maps for storing public keys and shared secrets by host
    private Map<String, String> PublicKeys; // Store dummy public key as String
    private Map<String, String> SharedSecrets; // Store dummy shared secret as String

    // Dummy "public key" of this node (just a String)
    private String myPublicKey;

    public ECDHRouter(Settings s) {
        super(s);
    }

    protected ECDHRouter(ECDHRouter r) {
        super(r);
        this.PublicKeys = new HashMap<>();
        this.SharedSecrets = new HashMap<>();
        generateKeyPair();
    }

    @Override
    public void init(DTNHost host, List<MessageListener> mListeners) {
		super.init(host, mListeners);
        generateKeyPair();
        PublicKeys.put(getHost().toString(), myPublicKey);
    }

    private void generateKeyPair() {
        // Simulate key generation by consuming energy, assign dummy key string
        this.myPublicKey = "PublicKey";
    }

    @Override
    public ECDHRouter replicate() {
        return new ECDHRouter(this);
    }

    @Override
    public void changedConnection(Connection con) {
        super.changedConnection(con);
        if (con.isUp()) {
            DTNHost peer = con.getOtherNode(getHost());
            sharePublicKey(peer);
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

    private void sharePublicKey(DTNHost peer) {
        ECDHRouter peerRouter = (ECDHRouter) peer.getRouter();

        // If peer doesn't have my public key, send it
        if (!peerRouter.hasPublicKey(getHost())) {
            String msgId = "ECDHPubKey" + getHost().toString();
            Message msg = new Message(getHost(), peer, msgId, myPublicKey.length());
            msg.addProperty("host", getHost());
            msg.addProperty("data", myPublicKey);
            createNewMessage(msg);
        }
    }

    private boolean hasPublicKey(DTNHost host) {
        return PublicKeys.containsKey(host.toString());
    }

    @Override
    public Message messageTransferred(String id, DTNHost from) {
        Message m = super.messageTransferred(id, from);
        if (m == null)
            return null;

        if (id.startsWith("ECDHPubKey")) {
            DTNHost host = (DTNHost) m.getProperty("host");
            String publicKey = (String) m.getProperty("data");
            if (!PublicKeys.containsKey(host.toString())) {
                PublicKeys.put(host.toString(), publicKey);
                this.energy.reduceEnergy(SHARED_SECRET_ENERGY);
                // Derive shared secret (dummy)
                String sharedSecret = "SharedSecret-" + getHost().toString() + "-" + host.toString();
                SharedSecrets.put(host.toString(), sharedSecret);
            }
        }
        return m;
    }

}
