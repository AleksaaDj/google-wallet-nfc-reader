package com.softwavegames.googlewalletnfcreader.passresponse;

import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.util.Log;

import com.softwavegames.googlewalletnfcreader.Utils;
import com.softwavegames.googlewalletnfcreader.exception.SmartTapException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class encapsulates the response from the `get smart tap data` command
 */
public class GetDataResponse {

    public String decryptedSmartTapRedemptionValue;

    /**
     * Constructor for the class
     *
     * @param response                             Byte array response
     * @param mobileDeviceEphemeralPublicKey       Mobile device ephemeral public key
     * @param terminalEphemeralPrivateKey          Terminal ephemeral private key
     * @param terminalNonce                        Terminal nonce
     * @param collectorId                          Collector ID
     * @param terminalEphemeralPublicKeyCompressed Terminal ephemeral public key
     * @param signedData                           Signed data
     * @param mobileDeviceNonce                    Mobile device nonce
     */
    public GetDataResponse(
            byte[] response,
            byte[] mobileDeviceEphemeralPublicKey,
            PrivateKey terminalEphemeralPrivateKey,
            byte[] terminalNonce,
            byte[] collectorId,
            byte[] terminalEphemeralPublicKeyCompressed,
            byte[] signedData,
            byte[] mobileDeviceNonce)
            throws Exception {

        try {
            // Extract status
            String status = Utils.getStatus(response);

            if (!status.startsWith("9")) {
                // Invalid status code
                throw new SmartTapException("Invalid status: " + status);
            }

            // Extract the service request NDEF record
            NdefRecord serviceRequestRecord = getServiceRequestRecord(Utils.extractPayload(response));

            // Extract the record bundle NDEF record
            NdefRecord recordBundleRecord = getRecordBundleNdefRecord(serviceRequestRecord);

            // Get and decrypt the `smartTapRedemptionValue` property from the card
            getDecryptedPayload(decrypt(
                    mobileDeviceEphemeralPublicKey,
                    terminalEphemeralPrivateKey,
                    terminalNonce,
                    mobileDeviceNonce,
                    collectorId,
                    terminalEphemeralPublicKeyCompressed,
                    signedData,
                    recordBundleRecord));

            if (decryptedSmartTapRedemptionValue == null || decryptedSmartTapRedemptionValue.isEmpty()) {
                throw new SmartTapException("Blank Smart Tap redemption value!");
            }
        } catch (Exception e) {
            throw new SmartTapException("Problem parsing `get smart tap data` response: " + e);
        }
    }

    /**
     * Get and decrypt the record bundle.
     *
     * @param mobileDeviceEphemeralPublicKey       Mobile device ephemeral public key
     * @param terminalEphemeralPrivateKey          Terminal ephemeral private key
     * @param terminalNonce                        Terminal nonce
     * @param mobileDeviceNonce                    Mobile device nonce
     * @param collectorId                          Collector ID
     * @param terminalEphemeralPublicKeyCompressed Terminal ephemeral public key
     * @param signedData                           Signed data
     * @param recordBundleRecord                   Record bundle NDEF record
     * @return Byte array record bundle
     */
    private static byte[] decrypt(
            byte[] mobileDeviceEphemeralPublicKey,
            PrivateKey terminalEphemeralPrivateKey,
            byte[] terminalNonce,
            byte[] mobileDeviceNonce,
            byte[] collectorId,
            byte[] terminalEphemeralPublicKeyCompressed,
            byte[] signedData,
            NdefRecord recordBundleRecord)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
            IllegalBlockSizeException, SmartTapException {

        // Generate the shared secret
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(terminalEphemeralPrivateKey);
        keyAgreement.doPhase(Utils.getPublicKeyFromBytes(mobileDeviceEphemeralPublicKey), true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Check the payload status (expecting uncompressed)
        byte status = recordBundleRecord.getPayload()[0];
        if (status == 2 || status == 3) {
            throw new SmartTapException("Expecting uncompressed payload!");
        }

        // Get the encrypted payload
        byte[] encryptedPayload = Arrays.copyOfRange(
                recordBundleRecord.getPayload(), 1, recordBundleRecord.getPayload().length);

        // Generate the shared key
        byte[] sharedKey = extractSharedKey(
                mobileDeviceEphemeralPublicKey,
                terminalNonce,
                mobileDeviceNonce,
                collectorId,
                terminalEphemeralPublicKeyCompressed,
                signedData,
                sharedSecret);
        byte[] expandedAesKey = Arrays.copyOfRange(sharedKey, 0, 16);
        byte[] ivBytes = Arrays.copyOfRange(encryptedPayload, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(encryptedPayload, 12, 12 + encryptedPayload.length - 44);
        SecretKey decryptionKey = new SecretKeySpec(expandedAesKey, "AES");

        // Check HMAC
        byte[] hmacKey = Arrays.copyOfRange(sharedKey, 16, sharedKey.length);
        checkHmac(encryptedPayload, hmacKey, ivBytes, ciphertext);

        // Decrypt the payload
        Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
        cipher.init(
                Cipher.DECRYPT_MODE,
                decryptionKey,
                new IvParameterSpec(
                        Utils.concatenateByteArrays(
                                ivBytes, new byte[4]))); // AES-CTR starts with 4-byte 0 counter

        return cipher.doFinal(ciphertext);
    }

    /**
     * Gets the shared key from the shared secret and mobile device ephemeral public key
     *
     * @param mobileDeviceEphemeralPublicKey       Mobile device ephemeral public key
     * @param terminalNonce                        Terminal nonce
     * @param mobileDeviceNonce                    Mobile devices nonce
     * @param collectorId                          Collector ID
     * @param terminalEphemeralPublicKeyCompressed Terminal ephemeral public key
     * @param signedData                           Signed data
     * @param sharedSecret                         Shared secret
     * @return Shared key in byte-array form
     */
    private static byte[] extractSharedKey(
            byte[] mobileDeviceEphemeralPublicKey,
            byte[] terminalNonce,
            byte[] mobileDeviceNonce,
            byte[] collectorId,
            byte[] terminalEphemeralPublicKeyCompressed,
            byte[] signedData,
            byte[] sharedSecret)
            throws IOException {

        byte[] info = Utils.concatenateByteArrays(
                terminalNonce,
                mobileDeviceNonce,
                collectorId,
                terminalEphemeralPublicKeyCompressed,
                signedData);

        Digest digest = new SHA256Digest();

        HKDFBytesGenerator hkdf2 = new HKDFBytesGenerator(digest);
        hkdf2.init(new HKDFParameters(sharedSecret, mobileDeviceEphemeralPublicKey, info));

        byte[] sharedKey = new byte[48];
        hkdf2.generateBytes(sharedKey, 0, sharedKey.length);

        return sharedKey;
    }

    /**
     * Checks the hash in the `get smart tap data` command response to ensure it was not tampered
     * with
     *
     * @param encryptedPayload Encrypted payload
     * @param hmacKey          Hash key
     * @param ivBytes          Initialization vector (part of hash)
     * @param ciphertext       Ciphertext (part of hash)
     */
    private static void checkHmac(
            byte[] encryptedPayload, byte[] hmacKey, byte[] ivBytes, byte[] ciphertext)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException, SmartTapException {

        byte[] receivedHmac = Arrays.copyOfRange(encryptedPayload, encryptedPayload.length - 32,
                encryptedPayload.length);

        SecretKey hashKey = new SecretKeySpec(hmacKey, "HmacSHA256");

        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(hashKey);

        byte[] derivedHmac = hmacSha256.doFinal(Utils.concatenateByteArrays(ivBytes, ciphertext));

        if (!Arrays.equals(receivedHmac, derivedHmac)) {
            // Message may have been tampered with
            throw new SmartTapException("Hash is incorrect!");
        }
    }

    /**
     * Gets the payload from a decrypted record bundle payload
     *
     * @param decrypted Decrypted record bundle payload
     */
    private void getDecryptedPayload(byte[] decrypted) throws FormatException {
        // Convert to NDEF message
        NdefMessage decryptedPayload = new NdefMessage(decrypted);

        // Iterate over payload NDEF records
        for (NdefRecord rec : decryptedPayload.getRecords()) {
            // Check for `asv` type
            if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x61, (byte) 0x73, (byte) 0x76})) {
                // Get the message payload
                NdefMessage serviceNdefRecord = new NdefMessage(rec.getPayload());

                // Iterate over service NDEF records
                for (NdefRecord serviceRecord : serviceNdefRecord.getRecords()) {
                    // Check for `ly` type
                    if (Arrays.equals(serviceRecord.getType(), new byte[]{(byte) 0x6c, (byte) 0x79})) {
                        // Get the loyalty record payload
                        NdefMessage loyaltyRecordPayload = new NdefMessage(serviceRecord.getPayload());

                        // Iterate over loyalty NDEF records
                        for (NdefRecord loyalty : loyaltyRecordPayload.getRecords()) {
                            // Check for `n` ID
                            if (Arrays.equals(loyalty.getId(), new byte[]{(byte) 0x6e})) {
                                // Get the Smart Tap redemption value
                                decryptedSmartTapRedemptionValue = new String(
                                        Arrays.copyOfRange(loyalty.getPayload(), 1, loyalty.getPayload().length));
                            }
                        }
                    }
                }
            }
        }
    }


    /**
     * Gets the record bundle NDEF record
     *
     * @param serviceRequestRecord Service request NDEF record
     * @return Record bundle ndef record
     */
    private static NdefRecord getRecordBundleNdefRecord(NdefRecord serviceRequestRecord)
            throws Exception {

        // Convert payload to service request payload NDEF message
        NdefMessage serviceRequestPayloadNdefMessage = new NdefMessage(
                serviceRequestRecord.getPayload());

        // Iterate over records in service request payload NDEF message
        for (NdefRecord rec : serviceRequestPayloadNdefMessage.getRecords()) {
            // Looking for `reb` type
            if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x72, (byte) 0x65, (byte) 0x62})) {
                // Found record bundle NDEF record
                return rec;
            }
        }

        throw new SmartTapException("No record bundle found!");
    }

    /**
     * Get the service request NDEF record from `get smart tap data` response
     *
     * @param payload Response from `get smart tap data`
     * @return Service request NDEF record
     */
    private static NdefRecord getServiceRequestRecord(byte[] payload) throws Exception {
        NdefRecord serviceRequestRecord = null;

        // Get the payload records
        NdefRecord[] records = (new NdefMessage(payload)).getRecords();

        // Iterate over the payload records
        for (NdefRecord rec : records) {
            // Looking for `srs` type
            if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x73, (byte) 0x72, (byte) 0x73})) {
                serviceRequestRecord = rec;
            }
        }

        // No `srs` record found
        if (serviceRequestRecord == null) {
            throw new SmartTapException("No service request record found!");
        }

        return serviceRequestRecord;
    }
}