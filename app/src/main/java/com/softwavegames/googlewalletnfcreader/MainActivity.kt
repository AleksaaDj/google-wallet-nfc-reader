package com.softwavegames.googlewalletnfcreader

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.softwavegames.googlewalletnfcreader.commands.GetDataCommand
import com.softwavegames.googlewalletnfcreader.commands.NegotiateCryptoCommand
import com.softwavegames.googlewalletnfcreader.databinding.ActivityMainBinding
import com.softwavegames.googlewalletnfcreader.passresponse.GetDataResponse
import com.softwavegames.googlewalletnfcreader.passresponse.NegotiateCryptoResponse
import com.softwavegames.googlewalletnfcreader.passresponse.SelectOSEResponse
import com.softwavegames.googlewalletnfcreader.passresponse.SelectSmartTapResponse
import org.bouncycastle.util.encoders.Hex
import java.util.Arrays

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private lateinit var binding: ActivityMainBinding
    private var nfcAdapter: NfcAdapter? = null
    private var arrayAdapter: ArrayAdapter<*>? = null
    private lateinit var output: ArrayList<String>
    private var inNfcSession = false
    private var negotiateCryptoResponse: NegotiateCryptoResponse? = null
    private var selectOSEResponse: SelectOSEResponse? = null
    private var selectSmartTapResponse: SelectSmartTapResponse? = null
    private var negotiateCryptoCommand: NegotiateCryptoCommand? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setNfcAdapter()

        val listView = binding.listView
        listView.adapter = arrayAdapter
    }

    private fun setNfcAdapter() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            Toast.makeText(this, "Device doesn't support NFC", Toast.LENGTH_SHORT).show()
            finish()
        }
        output = ArrayList()
        arrayAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, output)
    }

    override fun onTagDiscovered(tag: Tag) {
        try {
            output.clear()
            val isoDep = IsoDep.get(tag)
            isoDep.connect()
            if (output.size == 0 && !inNfcSession) {
                performSecureGetFlow(isoDep)
            }
            isoDep.close()
        } catch (e: Exception) {
            stopCommand(StringBuilder("Error: $e"))
        }
    }

    /**
     * Runs the individual commands in the `get smart tap data` flow and parses responses
     *
     * @param isoDep ISO-DEP (ISO 14443-4) tag methods
     */
    private fun performSecureGetFlow(isoDep: IsoDep) {
        inNfcSession = true

        // Outputs to the app during the flow
        val descriptiveText = StringBuilder("\nPerforming secure get flow...")

        try {
            // Command: `select ose`
            performSelectOSECommand(isoDep, descriptiveText)

            // Check for the Smart Tap AID
            var smartTap = false
            for (aid in selectOSEResponse!!.aids) {
                if (Arrays.equals(
                        aid,
                        byteArrayOf(
                            0xa0.toByte(),
                            0x00.toByte(),
                            0x00.toByte(),
                            0x04.toByte(),
                            0x76.toByte(),
                            0xd0.toByte(),
                            0x00.toByte(),
                            0x01.toByte(),
                            0x11.toByte()
                        )
                    )
                ) {
                    smartTap = true
                    break
                }
            }
            if (!smartTap) {
                // Smart TAP AID not present in `select ose` response
                descriptiveText.append("\n* Smart Tap AID not detected!\n---")

                // Stop
                stopCommand(descriptiveText)
                return
            }

            // Command: `select smart tap 2`
            performSelectSmartTap(isoDep, descriptiveText)

            // Command: `negotiate smart tap secure sessions`
            performNegotiateCrypto(isoDep, descriptiveText)

            // Command: `get smart tap data`
            performGetData(isoDep, descriptiveText)

            // Stop
            stopCommand(descriptiveText)
        } catch (e: Exception) {
            // Something went wrong...
            descriptiveText
                .append("\n\nError: ")
                .append(e)

            // Stop
            stopCommand(descriptiveText)
        }
    }

    /**
     * Performs `select ose` command and parses its response
     *
     * @param isoDep          ISO-DEP (ISO 14443-4) tag methods
     */
    @Throws(Exception::class)
    private fun performSelectOSECommand(isoDep: IsoDep, descriptiveText: StringBuilder) {
        val response = isoDep.transceive(
            byteArrayOf(
                0x00.toByte(),
                0xA4.toByte(),
                0x04.toByte(),
                0x00.toByte(),
                0x0A.toByte(),
                0x4F.toByte(),
                0x53.toByte(),
                0x45.toByte(),
                0x2E.toByte(),
                0x56.toByte(),
                0x41.toByte(),
                0x53.toByte(),
                0x2E.toByte(),
                0x30.toByte(),
                0x31.toByte(),
                0x00.toByte()
            )
        )
        selectOSEResponse = SelectOSEResponse(response)

        descriptiveText
            .append("\n----\nSent `select ose` command...\n")
            .append("\nResponse parsed:\n")

        // Response status

        // Response status
        descriptiveText
            .append("\n* Status:\n  ")
            .append(selectOSEResponse!!.status)
            .append(" (ISO 7816-4)\n")

        // Wallet application label

        // Wallet application label
        descriptiveText
            .append("\n* Wallet application label:\n  ")
            .append(selectOSEResponse!!.walletApplicationLabel)
            .append("\n")

        // Mobile device nonce

        // Mobile device nonce
        descriptiveText
            .append("\n* Mobile device nonce:\n  ")
            .append(Hex.toHexString(selectOSEResponse!!.mobileDeviceNonce))
            .append("\n")

        // Mobile device ephemeral key

        // Mobile device ephemeral key
        descriptiveText
            .append("\n* Mobile device ephemeral key:\n  ")
            .append(Hex.toHexString(selectOSEResponse!!.mobileDeviceEphemeralKey))
            .append("\n")

        // Application entries

        // Application entries
        for (app in selectOSEResponse!!.applications) {
            descriptiveText
                .append("\n* Application entry:\n  ")
                .append(app)
                .append("\n")
        }

        // End
        descriptiveText.append("\n----\n")
    }

    /**
     * Performs `select smart tap 2` and parses its response
     *
     * @param isoDep          ISO-DEP (ISO 14443-4) tag methods
     */
    @Throws(Exception::class)
    private fun performSelectSmartTap(isoDep: IsoDep, descriptiveText: StringBuilder) {
        val response = isoDep.transceive(
            byteArrayOf(
                0x00.toByte(),
                0xA4.toByte(),
                0x04.toByte(),
                0x00.toByte(),
                0x09.toByte(),
                0xA0.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x04.toByte(),
                0x76.toByte(),
                0xD0.toByte(),
                0x00.toByte(),
                0x01.toByte(),
                0x11.toByte(),
                0x00.toByte()
            )
        )
        selectSmartTapResponse = SelectSmartTapResponse(response)

        descriptiveText
            .append("\n----\nSent `select smart tap 2` command...\n")
            .append("\nResponse parsed:\n")

        // Status
        descriptiveText
            .append("\n* Status:\n  ")
            .append(selectSmartTapResponse!!.status)
            .append(" (ISO 7816-4)\n")

        // Minimum version
        descriptiveText
            .append("\n* Minimum Version:\n  ")
            .append(selectSmartTapResponse!!.minimumVersion)
            .append("\n")

        // Maximum version
        descriptiveText
            .append("\n* Maximum Version:\n  ")
            .append(selectSmartTapResponse!!.maximumVersion)
            .append("\n")

        if (selectSmartTapResponse!!.mobileDeviceNonce != null) {
            // Mobile device nonce
            descriptiveText
                .append("\n* Mobile Device Nonce:\n  ")
                .append(Hex.toHexString(selectSmartTapResponse!!.mobileDeviceNonce))
                .append("\n")
        }

        // End
        descriptiveText.append("\n----\n")
    }

    /**
     * Performs `negotiate smart tap secure sessions` and parses its response
     *
     * @param isoDep          ISO-DEP (ISO 14443-4) tag methods
     */
    @Throws(Exception::class)
    private fun performNegotiateCrypto(isoDep: IsoDep, descriptiveText: StringBuilder) {
        negotiateCryptoCommand = NegotiateCryptoCommand(
            selectSmartTapResponse?.mobileDeviceNonce
        )
        val response = isoDep.transceive(negotiateCryptoCommand!!.commandToByteArray())
        negotiateCryptoResponse = NegotiateCryptoResponse(response)

        descriptiveText
            .append("\n----\nSent `negotiate smart tap secure sessions` command...")
            .append("\nResponse parsed:\n")

        // Status last 4
        descriptiveText
            .append("\n* Status:\n  ")
            .append(negotiateCryptoResponse!!.status)
            .append(" (ISO 7816-4)\n")

        // Mobile device ephemeral public key
        descriptiveText
            .append("\n* Mobile device ephemeral public key (compressed):\n  ")
            .append(Hex.toHexString(negotiateCryptoResponse!!.mobileDeviceEphemeralPublicKey))
            .append('\n')

        // End
        descriptiveText.append("\n----\n")
    }

    /**
     * Performs `get smart tap data` and parses its response
     *
     * @param isoDep          ISO-DEP (ISO 14443-4) tag methods
     * @param descriptiveText Smart Tap response data to be surfaced on the device
     */
    @Throws(Exception::class)
    private fun performGetData(isoDep: IsoDep, descriptiveText: StringBuilder) {
        val getDataCommand = GetDataCommand(
            negotiateCryptoCommand!!.sessionId,
            negotiateCryptoCommand!!.collectorIdRecord,
            negotiateCryptoResponse!!.sequenceNumber + 1
        )
        val response = isoDep.transceive(getDataCommand.commandToByteArray())
        val getDataResponse = GetDataResponse(
            response,
            negotiateCryptoResponse!!.mobileDeviceEphemeralPublicKey,
            negotiateCryptoCommand!!.terminalEphemeralPrivateKey,
            negotiateCryptoCommand!!.terminalNonce,
            NegotiateCryptoCommand.COLLECTOR_ID,
            negotiateCryptoCommand!!.terminalEphemeralPublicKeyCompressed,
            negotiateCryptoCommand!!.signedData,
            selectSmartTapResponse!!.mobileDeviceNonce
        )
        descriptiveText.append("\n----\nSent `get smart tap data` command...")

        // Decrypted smartTapRedemptionValue from the pass
        descriptiveText.append("\nResponse parsed and decrypted, contents:\n  ")
        descriptiveText.append(getDataResponse.decryptedSmartTapRedemptionValue)

        // End
        descriptiveText.append("\n----\n")
    }

    /**
     * Stops the Smart Tap flow
     *
     * @param descriptiveText Smart Tap response data to be surfaced on the device
     */
    private fun stopCommand(descriptiveText: StringBuilder) {

        // Add output
        output.add(descriptiveText.toString())

        // Clear responses
        negotiateCryptoResponse = null
        selectOSEResponse = null
        selectSmartTapResponse = null
        negotiateCryptoCommand = null

        // Update the UI
        runOnUiThread {
            binding.openingMsg.visibility = View.GONE
            arrayAdapter!!.notifyDataSetChanged()
            inNfcSession = false
        }
    }

    override fun onResume() {
        super.onResume()
        var flags = NfcAdapter.FLAG_READER_NFC_A
        flags = flags or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        nfcAdapter?.enableReaderMode(this, this, flags, null)
    }

    public override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }
}