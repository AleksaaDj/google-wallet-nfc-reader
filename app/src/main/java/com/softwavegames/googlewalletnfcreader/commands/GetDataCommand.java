package com.softwavegames.googlewalletnfcreader.commands;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;


import com.softwavegames.googlewalletnfcreader.Utils;
import com.softwavegames.googlewalletnfcreader.exception.SmartTapException;

import java.io.IOException;

/**
 * Class encapsulates the creation of the `get smart tap data` command
 */
public class GetDataCommand {

    private static final byte[] COMMAND_PREFIX = new byte[]{
            (byte) 0x90,
            (byte) 0x50,
            (byte) 0x00,
            (byte) 0x00
    };

    private static final byte SERVICE_TYPE = 0x01;

    private NdefRecord serviceRequestRecord;

    /**
     * Constructor for the class
     *
     * @param sessionId         Session ID from context of Smart Tap
     * @param collectorIdRecord Collector ID NDEF record
     * @param sequenceNumber    The sequence number to use
     */
    public GetDataCommand(byte[] sessionId, NdefRecord collectorIdRecord, int sequenceNumber)
            throws Exception {

        try {
            NdefRecord sessionRecord = createSessionRecord(sessionId, sequenceNumber);
            NdefRecord merchantRecord = createMerchantRecord(collectorIdRecord);
            NdefRecord serviceListRecord = createServiceListRecord();
            createServiceRequestRecord(sessionRecord, merchantRecord, serviceListRecord);
        } catch (Exception e) {
            throw new SmartTapException("Problem creating `get smart tap data` command: " + e);
        }
    }

    /**
     * Creates a service request NDEF record from session, merchant, and service list NDEF records
     *
     * @param sessionRecord     Session NDEF record
     * @param merchantRecord    Merchant NDEF record
     * @param serviceListRecord Service list NDEF record
     */
    private void createServiceRequestRecord(
            NdefRecord sessionRecord, NdefRecord merchantRecord, NdefRecord serviceListRecord)
            throws IOException {

        // Service request NDEF record encapsulates all
        NdefMessage serviceRequestNdefMessagePayload = new NdefMessage(sessionRecord, merchantRecord,
                serviceListRecord);

        serviceRequestRecord = new NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                new byte[]{(byte) 0x73, (byte) 0x72, (byte) 0x71}, // `srq` in byte-array form
                null,
                Utils.concatenateByteArrays(
                        new byte[]{(byte) 0x00, (byte) 0x01}, // Service request ndef
                        serviceRequestNdefMessagePayload.toByteArray()));
    }

    /**
     * Creates a service list NDEF record
     *
     * @return Service list NDEF record
     */
    private static NdefRecord createServiceListRecord() {
        // Create a service type NDEF record that will go into the service list NDEF
        // record
        NdefRecord serviceTypeRecord = new NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                new byte[]{(byte) 0x73, (byte) 0x74, (byte) 0x72}, // `str` in byte-array form
                null,
                new byte[]{SERVICE_TYPE});
        NdefMessage serviceListRecordPayload = new NdefMessage(serviceTypeRecord);

        // Return the service list NDEF record
        return new NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                new byte[]{(byte) 0x73, (byte) 0x6C, (byte) 0x72}, // `slr` in byte array form
                null,
                serviceListRecordPayload.toByteArray());
    }

    /**
     * Creates merchant NDEF record
     *
     * @param collectorIdRecord Collector ID record portion of the merchant ID record
     * @return Merchant NDEF record
     */
    private static NdefRecord createMerchantRecord(NdefRecord collectorIdRecord) {
        return new NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                new byte[]{(byte) 0x6D, (byte) 0x65, (byte) 0x72}, // `mer` in byte-array form
                null,
                (new NdefMessage(collectorIdRecord).toByteArray()));
    }

    /**
     * Creates a session NDEF record using session ID
     *
     * @param sessionId      Smart Tap session ID
     * @param sequenceNumber The sequence number to use
     * @return Session NDEF record
     */
    private static NdefRecord createSessionRecord(byte[] sessionId, int sequenceNumber)
            throws IOException {
        return new NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x73}, // `ses` in byte-array form
                null,
                Utils.concatenateByteArrays(
                        sessionId,
                        new byte[]{(byte) sequenceNumber},
                        new byte[]{(byte) 0x01} // Status byte
                ));
    }

    /**
     * Converts an instance of this class into a byte-array `get smart tap data` command
     *
     * @return A byte array representing the command to send
     */
    public byte[] commandToByteArray() throws Exception {
        try {
            NdefMessage ndefMsg = new NdefMessage(serviceRequestRecord);
            int length = ndefMsg.getByteArrayLength();

            return Utils.concatenateByteArrays(
                    COMMAND_PREFIX,
                    new byte[]{(byte) length},
                    ndefMsg.toByteArray(),
                    new byte[]{(byte) 0x00});
        } catch (Exception e) {
            throw new SmartTapException(
                    "Problem turning `get smart tap data` command to byte array: " + e);
        }
    }
}
