package com.softwavegames.googlewalletnfcreader.passresponse;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;

import com.softwavegames.googlewalletnfcreader.Utils;
import com.softwavegames.googlewalletnfcreader.exception.SmartTapException;

import java.util.Arrays;

/**
 * Class encapsulates the response from the `negotiate secure smart tap sessions` command
 */
public class NegotiateCryptoResponse {

    public int sequenceNumber;
    public String status;
    public byte[] mobileDeviceEphemeralPublicKey;

    /**
     * Constructor for the class
     *
     * @param response Response from the `negotiate secure smart tap sessions` command
     */
    public NegotiateCryptoResponse(byte[] response) throws Exception {
        try {
            // Extract status
            this.status = Utils.getStatus(response);
            checkStatus();

            // Extract the negotiate request NDEF record
            NdefRecord negotiateRequestRecord = getNegotiateRequestRecord(Utils.extractPayload(response));

            // Iterate over inner request NDEF records
            for (NdefRecord rec : (new NdefMessage(negotiateRequestRecord.getPayload()).getRecords())) {
                // Looking for `ses`
                if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x73})) {
                    // Get the sequence number
                    sequenceNumber = rec.getPayload()[8];
                }
                // Looking for `dpk`
                if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x64, (byte) 0x70, (byte) 0x6B})) {
                    // Get the mobile device ephemeral public key
                    mobileDeviceEphemeralPublicKey = rec.getPayload();
                }
            }
        } catch (Exception e) {
            throw new SmartTapException(
                    "Problem parsing `negotiate secure smart tap sessions` response: " + e);
        }
    }

    /**
     * Checks the overall response status
     */
    private void checkStatus() throws Exception {
        // Check if status is valid
        if (!this.status.equals("9000")) {
            if (this.status.equals("9500")) {
                throw new SmartTapException("Unable to authenticate");
            } else {
                throw new SmartTapException("Invalid Status: " + this.status);
            }
        }
    }

    /**
     * Gets the negotiate request NDEF record from the response
     *
     * @param payload Byte-array of response
     * @return Negotiate request NDEF record
     */
    private static NdefRecord getNegotiateRequestRecord(byte[] payload) throws Exception {
        // Get records from the payload
        NdefRecord[] records = (new NdefMessage(payload)).getRecords();

        for (NdefRecord rec : records) {
            // Looking for `ngr`
            if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x6E, (byte) 0x72, (byte) 0x73})) {
                return rec;
            }
        }

        throw new SmartTapException("No record bundle found!");
    }
}
