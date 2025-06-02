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

public class NoKeyExchangeRouter extends ActiveRouter {

    private KeyPair KemKeyPair;
    private KeyPair SignKeyPair;

    private Map<String, PublicKey> PublicKeys = new HashMap<>();
    private Map<String, Boolean> MyPublicKeySent = new HashMap<>();
    private Map<String, int[]> SharedSecrets = new HashMap<>();
    private Map<String, Message> Ciphertexts = new HashMap<>();


    public NoKeyExchangeRouter(Settings s) {
        super(s);
    }

    /**
     * Copy constructor.
     * @param r The router prototype where setting values are copied from
     */
    protected NoKeyExchangeRouter(NoKeyExchangeRouter r) {
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
    public NoKeyExchangeRouter replicate() {
        return new NoKeyExchangeRouter(this);
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
            createNewMessage(msg);
        }
    }


    private void receivePublicKey(Message m, String type) {

        PublicKeys.put(m.getFrom().toString(), (PublicKey) m.getProperty("data"));
        ((NoKeyExchangeRouter) m.getFrom().getRouter()).ACK_PUBKEY(getHost());

        switch (type) {
            case "VerifyPubKey":

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

    }

    private Message createEncryptedMessage(Message m) {
        DTNHost origin = m.getFrom();
        String msgId = "CiphertextFrom" + getHost().toString();
        Message msg = new Message(getHost(), origin, msgId, 2000);
        createNewMessage(msg);
        return msg;
    }


    private void ACK_PUBKEY(DTNHost peer) {
        MyPublicKeySent.put(peer.toString(), true);
    }

}
