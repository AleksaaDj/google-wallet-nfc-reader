package com.softwavegames.googlewalletnfcreader.passresponse;

import android.nfc.NdefMessage;

import com.softwavegames.googlewalletnfcreader.Utils;
import com.softwavegames.googlewalletnfcreader.exception.SmartTapException;

import java.util.Arrays;

/**
 * Class encapsulates the response from the `select ose` command
 */
public class SelectSmartTapResponse {

    public String minimumVersion;
    public String maximumVersion;
    public String status;
    public byte[] mobileDeviceNonce;

    /**
     * Constructor for the class
     *
     * @param response Response from the `select smart tap 2` command
     */
    public SelectSmartTapResponse(byte[] response) throws Exception {
        // Extract status
        this.status = Utils.getStatus(response);

        if (!this.status.equals("9000")) {
            throw new SmartTapException("Invalid Status: " + this.status);
        }

        try {
            // Extract minimum and maximum versions
            byte[] payload = Utils.extractPayload(response);
            byte[] fourBytePayload = new byte[]{0x00, 0x00, payload[0], payload[1]};

            minimumVersion = Integer.toString((int) Utils.unsignedIntToLong(fourBytePayload));

            byte[] byteNum = Arrays.copyOfRange(response, 2, 4);
            byte[] fourByteNum = new byte[]{0x00, 0x00, byteNum[0], byteNum[1]};

            maximumVersion = Integer.toString((int) Utils.unsignedIntToLong(fourByteNum));

            // Extract mobile device nonce
            NdefMessage mdnNdefMessage = new NdefMessage(
                    Arrays.copyOfRange(response, 4, response.length - 2));
            this.mobileDeviceNonce = Arrays.copyOfRange(
                    mdnNdefMessage.getRecords()[0].getPayload(),
                    1,
                    mdnNdefMessage.getRecords()[0].getPayload().length);
        } catch (Exception e) {
            throw new SmartTapException("Problem parsing `select smart tap 2` response: " + e);
        }
    }
}
