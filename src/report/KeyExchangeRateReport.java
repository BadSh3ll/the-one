/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */
package report;

import core.DTNHost;
import core.Message;
import core.MessageListener;

/**
 * Reports delivered messages
 * report:
 *  message_id creation_time deliver_time (duplicate)
 */
public class KeyExchangeRateReport extends Report implements MessageListener {
	public static final String HEADER =
	    "Key Exchange Rate Report\n";
	/** all message delays */

	private static int successCount = 0;
	private static int failureCount = 0;

	/**
	 * Constructor.
	 */
	public KeyExchangeRateReport() {
		init();
	}

	@Override
	public void init() {
		super.init();
		write(HEADER);
	}


	public void ExchangeSuccess() {
        successCount++;
    }

    public void ExchangeFailure() {
        failureCount++;
    }


	@Override
	public void done() {
	    write("Key Exchange Success Count: " + successCount);
        write("Key Exchange Failure Count: " + failureCount);
        successCount = 0;
        failureCount = 0;
		super.done();
	}

	public void newMessage(Message m) {};
	public void messageTransferStarted(Message m, DTNHost from, DTNHost to) {};
	public void messageDeleted(Message m, DTNHost where, boolean dropped) {};
	public void messageTransferAborted(Message m, DTNHost from, DTNHost to) {};
	public void messageTransferred(Message m, DTNHost from, DTNHost to,
			boolean firstDelivery) {}


}
