package com.vzsim.minihsm;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;

public class CryptoKey extends Applet implements ISO7816
{
	private static final short ZERO = (short)0;
	private static final short THIRTY_TWO = (short)32;
	private static final short SIXTY_FOUR = (short)64;

	private static final short SW_PIN_TRIES_REMAINING      = (short)0x63C0; // See ISO 7816-4 section 7.5.1
	private static final short SW_ARRAY_INDEX_OUT_OF_RANGE = (short)0x6703;

	private static final short SW_CRYPTO_EXCEPTION                = (short)0x6600;
	private static final short SW_CRYPTO_SHARED_CHECKSUM_MISMATCH = (short)0x6606;

	/* Constant values */
	private static final byte INS_GET_DATA				= (byte)0xCA;
	private static final byte INS_VERIFY                = (byte)0x20;
	private static final byte INS_OPEN_SM               = (byte)0x22;
    private static final byte INS_CHANGE_REFERENCE_DATA = (byte)0x25;
	private static final byte INS_RESET_RETRY_COUNTER   = (byte)0x2D;

	private static final byte PIN_MAX_TRIES             = (byte)0x03;
	private static final byte PUK_MAX_TRIES             = (byte)0x0A;
	private static final byte PIN_MIN_LENGTH            = (byte)0x04;
	private static final byte PIN_MAX_LENGTH            = (byte)0x10;
	
	private static final short APPLET_STATE_OFFSET_SM   = (short)0x00;
	private static final byte SM_STATE_ESTABLISHED      = (byte)0xA5;

	/** No restrictions */
	private static final byte APP_STATE_CREATION        = (byte)0x01;
	
	/** PUK set, but PIN not set yet. */
	private static final byte APP_STATE_INITIALIZATION  = (byte)0x02;

	/** PIN is set. data is secured. */
	private static final byte APP_STATE_ACTIVATED       = (byte)0x05;

	/** Applet usage is deactivated. */
	private static final byte APP_STATE_DEACTIVATED     = (byte)0x04;

	/** Applet usage is terminated. */
	private static final byte APP_STATE_TERMINATED      = (byte)0x0C;

	private static final byte API_VERSION_MAJOR			= (byte)0x00;
	private static final byte API_VERSION_MINOR			= (byte)0x01;

	/** "InterGalaxy" */
	private static final byte[] MANUFACTURER = {
		(byte)11,
		(byte)'I', (byte)'n', (byte)'t', (byte)'e', (byte)'r', (byte)'G', (byte)'a', (byte)'l', (byte)'a', (byte)'x', (byte)'y'
	};
	
	/** "MiniHSM" */
	private static final byte[] MODEL = {
		(byte)4,
		(byte)'e', (byte)'S', (byte)'I', (byte)'M'
	};

	/** 31121985 */
	private static final byte[] SERIAL_NUMBER = {
		(byte)8,
		(byte)'3', (byte)'1', (byte)'1', (byte)'2',(byte)'1', (byte)'9', (byte)'8', (byte)'5'
	};

	private byte     LCS;
	private byte[]   appletState;
	private OwnerPIN pin;
	private OwnerPIN puk;
	private byte[]   TOKEN_LABEL;

	private KeyPair      ecFPPair;
	private ECPrivateKey ecFPprivKey;
	private ECPublicKey  ecFPpubKey;
	private KeyAgreement ecDhPlain;
	private byte[]       sharedSecret;

	private AESKey aesEphem;
	private Cipher aesENC;
	private Cipher aesDEC;

	private RandomData rand;

	public CryptoKey()
	{
		puk = new OwnerPIN(PUK_MAX_TRIES, PIN_MAX_LENGTH);
		pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);

		ecFPPair       = ECCurves.getKeyPair(ECCurves.EC_SecP256k1);
		TOKEN_LABEL    = new byte[33];
		TOKEN_LABEL[0] = (byte)0;
		ecDhPlain      = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		sharedSecret   = JCSystem.makeTransientByteArray(SIXTY_FOUR, JCSystem.CLEAR_ON_DESELECT);
		aesEphem       = (AESKey)KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_AES, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		aesENC         = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M1, false);
		aesDEC         = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M1, false);
		rand           = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);

		appletState    = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);

		LCS = APP_STATE_CREATION;
		appletState[APPLET_STATE_OFFSET_SM] = ~SM_STATE_ESTABLISHED;
	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new CryptoKey().register();
	}
	
	public void	process(APDU apdu) throws ISOException
	{
		if (selectingApplet()) {
			appletState[APPLET_STATE_OFFSET_SM] = ~SM_STATE_ESTABLISHED;
			return;
		}

		short le = 0, lc = 0;
		byte[] buff    = apdu.getBuffer();
		byte ins       = buff[OFFSET_INS];
		byte p1        = buff[OFFSET_P1];

		short cdataOff = apdu.getOffsetCdata();

		if (LCS == APP_STATE_TERMINATED) {
			ISOException.throwIt((short)(SW_UNKNOWN | APP_STATE_TERMINATED));
		}
		
		try {
			if (isCase3Case4Command((short)((short)ins << (short)8 | (short)p1 & (short)0x00FF))) {
				lc = apdu.setIncomingAndReceive();
				if (lc != apdu.getIncomingLength()) {
					ISOException.throwIt(SW_WRONG_LENGTH);
				}
			}

			switch (ins) {
				case INS_GET_DATA: {
					le = getData(buff);
				} break;
				case INS_VERIFY: {
					le = verify(buff, cdataOff, lc);
				} break;
				case INS_OPEN_SM: {
					le = openSecureMessagingSession(buff, cdataOff, lc);
				} break;
				case INS_CHANGE_REFERENCE_DATA: {
					le = changeReferenceData(buff, cdataOff, lc);
				} break;
				case INS_RESET_RETRY_COUNTER: {
					le = resetRetryCounter(buff, cdataOff, lc);
				} break;
				default: {
					ISOException.throwIt(SW_INS_NOT_SUPPORTED);
				}
			}

			if (le > ZERO) {
				apdu.setOutgoingAndSend(ZERO, le);
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			ISOException.throwIt(SW_ARRAY_INDEX_OUT_OF_RANGE);
		}
		catch (CryptoException e) {
			short reason = (short)(e.getReason() & (short)0x00FF);
			ISOException.throwIt((short)(SW_CRYPTO_EXCEPTION | reason));
		}
	}

	/**
	 * CHANGE REFERENCE DATA (INS = 0x25), ISO 7816-4, clause 11.5.7.
	 * <p>
	 * CDATA shall contain BER-TLV data object (ISO 7816-4, clause 6.3) to make it possible to
	 * distinguish one type of data from another (i.e. current PIN and new PIN).
	 * <p>
	 * This method handles the following data at specific Life cycle states:
	 * <ul>
	 * 	<li>APP_STATE_CREATION			<p>[81 Len <Initial PUK bytes>]
	 * 	<li>APP_STATE_INITIALIZATION	<p>[81 Len <Initial PIN bytes>]
	 * 	<li>APP_STATE_ACTIVATED			<p>[81 Len <CURR PIN bytes> 82 Len <NEW PIN bytes>]
	 * </ul>
	 * @param apdu
	 */
	private short changeReferenceData(byte[] buff, short cdataOff, short lc)
	{
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];
		short len = 0, off = 0;

		if (lc == ZERO) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		// Common case for each LCS: either PIN or PUK.
		len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x81);
		off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x81);

		if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		
		switch (LCS) {

			case APP_STATE_CREATION: {	// Set PUK

				if (p2 != (byte)0x01 && p2 != (byte)0x02) {
					ISOException.throwIt(SW_INCORRECT_P1P2);
				}

				puk.update(buff, off, (byte)len);
				puk.resetAndUnblock();
				
				len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x82);
				off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x82);
				
				// (off - 1) means 'grab the length too'.
				Util.arrayCopyNonAtomic(buff, (short)(off - (short)1), TOKEN_LABEL, (short)0, (short)(len + (short)1));
				LCS = APP_STATE_INITIALIZATION;

			} break;
			case APP_STATE_INITIALIZATION: {	// Set PIN

				if (p1 != (byte)0x01 || p2 != (byte)0x01) {
					ISOException.throwIt(SW_INCORRECT_P1P2);
				}

				pin.update(buff, off, (byte)len);
				pin.resetAndUnblock();

				ecFPPair.genKeyPair();
				ecFPprivKey = (ECPrivateKey)ecFPPair.getPrivate();
				ecFPpubKey  = (ECPublicKey)ecFPPair.getPublic();
				ecDhPlain.init(ecFPprivKey);

				LCS = APP_STATE_ACTIVATED;
				
			} break;
			case APP_STATE_ACTIVATED: {	// Update PIN

				if (p1 != ZERO || p2 != ZERO) {
					ISOException.throwIt(SW_INCORRECT_P1P2);
				}

				// Check the old PIN
				if (!pin.check(buff, off, (byte)len)) {
					ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
				}

				len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x82);
				off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x82);

				if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
					ISOException.throwIt(SW_WRONG_DATA);
				}

				// Update PIN
				pin.update(buff, off, (byte)len);
				pin.resetAndUnblock();

			} break;
			default: ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}
		return ZERO;
	}

	/**
	 * VERIFY (INS = 0x20), ISO 7816-4, clause 11.5.6.
	 * @param buff
	 * @param cdataOff
	 * @param lc
	 * @return
	 */
	private short verify(byte[] buff, short cdataOff, short lc)
	{
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];

		byte appState = LCS;

		if (appState == APP_STATE_DEACTIVATED) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		if (p1 != ZERO || p2 != (byte)0x01) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		// At the CREATION and INITIALIZATION states no PIN is set yet, thus there is no error at all.
		if (lc == ZERO && (appState <= APP_STATE_INITIALIZATION)) {
			ISOException.throwIt(SW_NO_ERROR);
		} else if (lc == ZERO && (appState == APP_STATE_ACTIVATED)) {
			// The absence of CDATA means that a user requested the number of remaining tries.
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		}

		if (lc < PIN_MIN_LENGTH || lc > PIN_MAX_LENGTH) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		// Check the PIN.
		if (!pin.check(buff, cdataOff, (byte)lc)) {

			if (pin.getTriesRemaining() < (byte)1) {
				LCS = APP_STATE_DEACTIVATED;
			}

			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		}
		return ZERO;
	}

	/**
	 * RESET RETRY COUNTER (INS = 0x2D), ISO 7816-4, clause 11.5.10.
	 * <p>
	 * Supported combinations are:
	 * <ul>
	 * 	<li> P1 == 0 CDATA: [81 Len PUK && 82 Len NEW PIN]	// appying new PIN
	 * 	<li> P1 == 1 CDATA: [81 Len PUK]					// Just reset PIN tries counter
	 * 	<li> P3 == 3 CDATA: absent							// get PUK remaining tries
	 * </ul>
	 * As for changing the PIN, unlike changeReferenceData() method, this one updates it if and only if
	 * a user have submitted the PUK.
	 * @param buff     incoming data (either PIN or PUK)
	 * @param cdataOff an offset within buff
	 * @param lc       a length of incoming data
	 */
	private short resetRetryCounter(byte[] buff, short cdataOff, short lc)
	{
		byte p1 = buff[OFFSET_P1];
		short len, off;

		if (LCS != APP_STATE_DEACTIVATED || puk == null) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		if (p1 < (byte)ZERO || p1 > (byte)0x03) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		// PUK tries counter requested.
		if (p1 == (byte)0x03) {
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
		}

		// Common case for P1=0 and P1=1: retrieving PUK
		len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x81);
		off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x81);

		if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
			ISOException.throwIt((short)(SW_WRONG_DATA + (short)1));
		}

		if (!puk.check(buff, off, (byte)len)) {
			if (puk.getTriesRemaining() < (byte)1) {
				LCS = APP_STATE_TERMINATED;
			}
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
		}

		// P1=0: apply a new PIN value.
		if (p1 == ZERO) {
			
			off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x82);
			len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x82);

			if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
				ISOException.throwIt(SW_WRONG_DATA);
			}

			pin.update(buff, off, (byte)len);
		}

		// Common case for P1=0 and P1=1: reset and unblock PIN
		pin.resetAndUnblock();
		LCS = APP_STATE_ACTIVATED;

		return ZERO;
	}
	
	/**
	 * GENERATE SHARED SECRET (INS = 0x22), ISO 7816-4, clause 11.5.11.
	 * @param buff
	 * @param cdataOff
	 * @param lc
	 * @return
	 */
	private short openSecureMessagingSession(byte[] buff, short cdataOff, short lc)
	{
		short le = 0;
		byte p1 = 0;

		p1 = buff[OFFSET_P1];

		if (LCS != APP_STATE_ACTIVATED) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		switch (p1) {
			case (byte)0x00: // generate shared secret
				
				// using host's public key, generate a shared secret
				ecDhPlain.generateSecret(buff, cdataOff, lc, sharedSecret, ZERO);
				
				// prepare the public key to be sent back to the host
				le = ecFPpubKey.getW(buff, ZERO);

				// send back the shared secret so that we could compare it
				le = Util.arrayCopyNonAtomic(sharedSecret, ZERO, buff, le, THIRTY_TWO);

				// Use the first bytes of the shared secret as AES key.
				// aesEphem.setKey(sharedSecret, ZERO);

				// Initialize aes ciphers.
				// aesENC.init(aesEphem, Cipher.MODE_ENCRYPT);
				// aesDEC.init(aesEphem, Cipher.MODE_DECRYPT);

				

				// generate a random value and send it to the host.
				// rand.generateData(buff, SIXTEEN, SIXTEEN);
				// le += SIXTEEN;

				// Calculate the checksum on the random data and store it temporarily.
				// aesENC.doFinal(buff, SIXTEEN, SIXTEEN, sharedSecret, ZERO);

			break;
			case (byte)0x01: // verify shared
				
				if (Util.arrayCompare(buff, cdataOff, sharedSecret, ZERO, lc) == ZERO) {
					appletState[APPLET_STATE_OFFSET_SM] = SM_STATE_ESTABLISHED;
				} else {
					ISOException.throwIt(SW_CRYPTO_SHARED_CHECKSUM_MISMATCH);
				}
				
				le = ZERO;
			break;
			case (byte)0x02:	// test case - get the private key which will be used on the host side
				le = ecFPprivKey.getS(buff, (short)1);
				buff[ZERO] = (byte)le;
				le += (short)1;
			break;
		}

		return le;
	}

	/**
	 * GET DATA apdu (INS = 0xCA), ISO 7816-4, clause 11.4.3.
	 * <b>
	 * @param buff pointer to the APDU buffer
	 */
	private short getData(byte[] buff)
	{
		short p1p2  = (short)((short)buff[OFFSET_P1] << (short)8);
		      p1p2 |= (short)((short)buff[OFFSET_P2] & (short)0x00FF);

		short offset = ZERO;
		switch (p1p2) {
			case (short)0x00FF: {
				buff[offset++] = LCS;
				buff[offset++] = API_VERSION_MAJOR;
				buff[offset++] = API_VERSION_MINOR;
				buff[offset++] = PIN_MIN_LENGTH;
				buff[offset++] = PIN_MAX_LENGTH;

				offset = Util.arrayCopyNonAtomic(MANUFACTURER,  (short)0, buff, offset, (short)((short)MANUFACTURER[0]  + (short)1));
				offset = Util.arrayCopyNonAtomic(TOKEN_LABEL,   (short)0, buff, offset, (short)((short)TOKEN_LABEL[0]   + (short)1));
				offset = Util.arrayCopyNonAtomic(MODEL,         (short)0, buff, offset, (short)((short)MODEL[0]         + (short)1));
				offset = Util.arrayCopyNonAtomic(SERIAL_NUMBER, (short)0, buff, offset, (short)((short)SERIAL_NUMBER[0] + (short)1));
			} break;
			default: ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		return offset;
	}

	private boolean isCase3Case4Command(short cmd)
	{
		boolean result;

		switch (cmd) {
			case (short)0x2000: // verify
			case (short)0x2200: // Establish SM: generate shared
			case (short)0x2201: // Establish SM: verify shared
			case (short)0x2500:	// change ref data
			case (short)0x2501:	// change ref data
			case (short)0x2D00: // reset retry counter: activate card and set new PIN
			case (short)0x2D01: // reset retry counter: activate card and reset PIN
				result = true;
			break;
			default: result = false;
		}
		return result;
	}
}