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
	private static final short ZERO       = (short)0;
	private static final short SIXTEEN    = (short)16;
	private static final short THIRTY_TWO = (short)32;
	private static final short SIXTY_FOUR = (short)64;

	private static final short SW_PIN_TRIES_REMAINING      = (short)0x63C0; // See ISO 7816-4 section 7.5.1
	private static final short SW_ARRAY_INDEX_OUT_OF_RANGE = (short)0x6703;

	private static final short SW_CRYPTO_EXCEPTION                = (short)0x6600;
	// private static final short SW_CRYPTO_SHARED_CHECKSUM_MISMATCH = (short)0x6606;

	/** The set of supported INStructions */
	private static final byte INS_GET_DATA              = (byte)0xCA;
	private static final byte INS_VERIFY                = (byte)0x20;
	private static final byte INS_GEN_SHARED_SECRET     = (byte)0x22;
    private static final byte INS_CHANGE_REFERENCE_DATA = (byte)0x25;
	private static final byte INS_PSO                   = (byte)0x2A;
	private static final byte INS_RESET_RETRY_COUNTER   = (byte)0x2D;
	private static final byte INS_DEACTIVATE            = (byte)0x04;
	private static final byte INS_ACTIVATE              = (byte)0x44;
	private static final byte INS_TERMINATE             = (byte)0xE6;


	private static final byte PIN_MAX_TRIES             = (byte)0x03;
	private static final byte PUK_MAX_TRIES             = (byte)0x0A;
	private static final byte PIN_MIN_LENGTH            = (byte)0x04;
	private static final byte PIN_MAX_LENGTH            = (byte)0x10;
	
	/** Offsets within byte[] appletState array*/
	private static final short OFFSET_APP_STATE_SM      = (short)0x00;
	private static final short OFFSET_APP_STATE_PIN     = (short)0x01;

	/** Secure Messaging is established. The inverse value designates opposite state. */
	private static final byte  APP_STATE_SM_ESTABLISHED = (byte)0xA5;

	/** No restrictions */
	private static final byte APP_STATE_INITIALIZATION  = (byte)0x03;

	/** Some operations are available only after presenting a PIN. */
	private static final byte APP_STATE_ACTIVATED       = (byte)0x05;

	/** To return the applet to the ACTIVATED state a PUK must be presented. */
	private static final byte APP_STATE_DEACTIVATED     = (byte)0x04;

	/** There is no chance to return the applet to the ACTIVATED state.
	 * The only option left is to erase entire memory by means of presenting the PUK. */
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
	private byte[]       tempRamBuff;

	private AESKey aesKey16;
	private Cipher aesCipher;

	private RandomData rand;

	public CryptoKey()
	{
		puk = new OwnerPIN(PUK_MAX_TRIES, PIN_MAX_LENGTH);
		pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);

		ecFPPair       = ECCurves.getKeyPair(ECCurves.EC_SecP256k1);
		TOKEN_LABEL    = new byte[33];
		TOKEN_LABEL[0] = (byte)0;
		ecDhPlain      = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		tempRamBuff    = JCSystem.makeTransientByteArray((short)(SIXTY_FOUR * (short)4), JCSystem.CLEAR_ON_RESET);
		aesKey16       = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aesCipher      = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M1, false);

		rand           = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);

		appletState    = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_RESET);

		LCS = APP_STATE_INITIALIZATION;
		appletState[OFFSET_APP_STATE_SM] = ~APP_STATE_SM_ESTABLISHED;
		appletState[OFFSET_APP_STATE_PIN] = ZERO;
	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new CryptoKey().register();
	}
	
	public void	process(APDU apdu) throws ISOException
	{
		if (selectingApplet()) {
			appletState[OFFSET_APP_STATE_SM]  = ~APP_STATE_SM_ESTABLISHED;
			appletState[OFFSET_APP_STATE_PIN] = ZERO;
			return;
		}

		short le = 0, lc = 0;
		byte[] buff = apdu.getBuffer();
		byte ins    = buff[OFFSET_INS];
		byte p1     = buff[OFFSET_P1];

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
				case INS_GEN_SHARED_SECRET: {
					le = generateSharedSecret(buff, cdataOff, lc);
				} break;
				case INS_CHANGE_REFERENCE_DATA: {
					le = changeReferenceData(buff, cdataOff, lc);
				} break;
				case INS_PSO: {
					le = performSecurityOperation(buff, cdataOff, lc);
				} break;
				case INS_RESET_RETRY_COUNTER: {
					le = resetRetryCounter(buff, cdataOff, lc);
				} break;
				case INS_DEACTIVATE:
				case INS_ACTIVATE:
				case INS_TERMINATE:
					le = lcsManagement(buff, cdataOff, lc);
				break;
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
	 * This method supports the following operations:
	 * <ul>
	 * 	<li> SET PUK:           <b> [P1=00, P2=01] [81 Len [PUK] ] </b>
	 * 	<li> SET PIN:           <b> [P1=00, P2=02] [81 Len [PIN] ] </b>
	 * 	<li> UPD PIN:           <b> [P1=00, P2=03] [81 Len [CURR PIN] 82 Len [NEW PIN] ] </b>
	 *  <li> SET LABEL:         <b> [P1=00, P2=04] [81 Len [LABEL] ] </b>
	 *  <li> CREATE/UPDATE AES: <b> [P1=00, P2=05] [81 Len [KEY MATERIAL] ] </b>
	 *  <li> CREATE/UPDATE AES: <b> [P1=01, P2=05] </b>
	 *  <li> GEN ECDSA:         <b> [P1=01, P2=07] </b>
	 * </ul>
	 */
	private short changeReferenceData(byte[] buff, short cdataOff, short lc)
	{
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];
		short len = 0, off = 0;

		
		// Fetch the CDATA.
		if (p1 == ZERO) {
			if (lc == ZERO) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x81);
			off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x81);
		}

		if (p2 <= (byte)0x03 && (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1)) {
			ISOException.throwIt(SW_WRONG_DATA);
		}

		if (p2 == (byte)0x04 && len > THIRTY_TWO) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		switch (p2) {

			case (byte)0x01: // Set PUK
			{
				puk.update(buff, off, (byte)len);
				puk.resetAndUnblock();
			} break;
			case (byte)0x02: // Set PIN
			{
				pin.update(buff, off, (byte)len);
				pin.resetAndUnblock();
				
			} break;
			case (byte)0x03: // Update PIN
			{
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
			case (byte)0x04: // Set LABEL
			{
				// (off - 1) means 'grab the length too'.
				Util.arrayCopyNonAtomic(buff, (short)(off - (short)1), TOKEN_LABEL, (short)0, (short)(len + (short)1));
			} break;
			case (byte)0x05: // Create/update AES
			{
				// p1=0x00 means that a key material is passed over in CDATA and its length must be 16 bytes.
				// if (p1 == ZERO && (len != SIXTEEN || off == (short)-1)) {
				// 	ISOException.throwIt(SW_WRONG_DATA);
				// } else {
				// 	// Otherwise, generate a random 16 bytes that will be used as key material.
				// 	off = ZERO;
				// 	rand.generateData(buff, off, len);
				// }

				if (p1 == ZERO && (len != SIXTEEN || off == (short)-1)) {
					ISOException.throwIt(SW_WRONG_DATA);
				}
				aesKey16.setKey(buff, off);

				// Initialize aes ciphers.
				aesCipher.init(aesKey16, Cipher.MODE_ENCRYPT);
			} break;
			case (byte)0x07: // Create ECDSA
			{
				ecFPPair.genKeyPair();
				ecFPprivKey = (ECPrivateKey)ecFPPair.getPrivate();
				ecFPpubKey  = (ECPublicKey)ecFPPair.getPublic();
				ecDhPlain.init(ecFPprivKey);
			} break;
			default: ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}
		return ZERO;
	}


	/**
	 * PERFORM SECURITY OPERATION (INS = 0x2A), ISO 7816-8, clause 5.3.
	 * 
	 * 
	 * @param buff
	 * @param cdataOff
	 * @param lc
	 * @return
	 */
	private short performSecurityOperation(byte[] buff, short cdataOff, short lc)
	{
		short le = ZERO;

		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];
		short cmd  = (short)(((short)p1 << (short)8) | ((short)p2 & (short)0x00FF));

		// The ISO 7816-8, clause 5.3.1 states: "for this command, when verification related operation
		// is considered, SW1-SW2 set to '6300' or '63CX' indicates that a verification failed."
		// TODO: we need to specify what commads that paragraph talk about. Till that moment is't assumed
		// that ALL commands might be performed only after PIN verification.
		if (LCS != APP_STATE_ACTIVATED && appletState[OFFSET_APP_STATE_PIN] != ~ZERO) {
			ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		if (lc == ZERO) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		switch (cmd) {
			case (short)0x8084: { // ISO 7816-8, clause 5.3.9
				le = decipher(buff, cdataOff, lc);
			} break;
			case (short)0x8480: { // ISO 7816-8, clause 5.3.8
				le = encipher(buff, cdataOff, lc);
			} break;
			default: {
				ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
			}
		}
		return le;
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

		byte appState = LCS;

		if (appState == APP_STATE_DEACTIVATED) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		if (p1 != ZERO && p1 != ~ZERO) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		// At the CREATION and INITIALIZATION states no PIN is set yet, thus there is no error at all.
		if (lc == ZERO && (appState <= APP_STATE_INITIALIZATION)) {
			ISOException.throwIt(SW_NO_ERROR);
		} else if ((p1 == ~ZERO) && (lc == ZERO) && (appState == APP_STATE_ACTIVATED)) {
			// Set verification status to 'not verified'
			appletState[OFFSET_APP_STATE_PIN] = ZERO;
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
			
			appletState[OFFSET_APP_STATE_PIN] = ZERO;
			if (pin.getTriesRemaining() < (byte)1) {
				LCS = APP_STATE_DEACTIVATED;
			}

			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		}

		appletState[OFFSET_APP_STATE_PIN] = ~ZERO;
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
	 * ACTIVATE (INS = 0x44), ISO 7816-9, clause 6.5<p>
	 * ACTIVATE (INS = 0x04), ISO 7816-9, clause 6.4<p>
	 * ACTIVATE (INS = 0xE6), ISO 7816-9, clause 6.6<p>
	 * 
	 * @param buff
	 * @param cdataOff
	 * @param lc
	 * @return
	 */
	private short lcsManagement(byte[] buff, short cdataOff, short lc)
	{
		short le = ZERO;
		byte ins = buff[OFFSET_INS];
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];

		if (p1 != (byte)0x30 && p2 != (byte)ZERO) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		switch (ins) {
			case INS_DEACTIVATE:
				LCS = APP_STATE_DEACTIVATED;
			break;
			case INS_ACTIVATE:
				LCS = APP_STATE_ACTIVATED;
			break;
			case INS_TERMINATE:
				LCS = APP_STATE_TERMINATED;
			break;
		}
		return le;
	}

	/**
	 * GENERATE SHARED SECRET (INS = 0x22), ISO 7816-4, clause 11.5.11.
	 * @param buff
	 * @param cdataOff
	 * @param lc
	 * @return 65 bytes of token's public key followed by a shared secret.
	 */
	private short generateSharedSecret(byte[] buff, short cdataOff, short lc)
	{
		short le = ZERO;
		byte p1 = buff[OFFSET_P1];

		if (p1 != ZERO) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		if (LCS != APP_STATE_ACTIVATED || appletState[OFFSET_APP_STATE_PIN] != ~ZERO) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		// generate a shared secret by means of host's public key
		ecDhPlain.generateSecret(buff, cdataOff, lc, tempRamBuff, ZERO);
		
		// Fetch the public key to be sent back
		le = ecFPpubKey.getW(buff, ZERO);

		// copy card's shared secret into the outgoing buffer.
		le = Util.arrayCopyNonAtomic(tempRamBuff, ZERO, buff, le, THIRTY_TWO);

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

	
	/**
	 * Performs encryption of the input data using an algorithm specified in ... (TODO)
	 * 
	 * @apiNote data must be encoded in BER-TLV format.
	 * 
	 * @param buff a plaintext.
	 * @param cdataOff offset within buffer
	 * @param lc the length on plaintext
	 * @return the length of cryptogram
	 */
	private short encipher(byte[] buff, short cdataOff, short lc)
	{
		short le = ZERO;
		aesCipher.init(aesKey16, Cipher.MODE_ENCRYPT);
		le = aesCipher.update(buff, cdataOff, lc, tempRamBuff, ZERO);
		le = aesCipher.doFinal(tempRamBuff, ZERO, le, buff, ZERO);

		return le;
	}


	/**
	 * Performs decryption of the input data using an algorithm specified in ... (TODO)
	 * @param buff a cryptogram.
	 * @param cdataOff offset within buff
	 * @param lc the length on the cryptogram
	 * @return the length of plaintext
	 */
	private short decipher(byte[] buff, short cdataOff, short lc)
	{
		short le = ZERO;
		aesCipher.init(aesKey16, Cipher.MODE_DECRYPT);
		le = aesCipher.update(buff, cdataOff, lc, tempRamBuff, ZERO);
		le = aesCipher.doFinal(tempRamBuff, ZERO, le, buff, ZERO);

		return le;
	}


	private boolean isCase3Case4Command(short cmd)
	{
		boolean result;

		switch (cmd) {
			case (short)0x2A80: // PSO decrypt
			case (short)0x2A84: // PSO encrypt
			case (short)0x2000: // verify
			case (short)0x2200: // Establish SM: generate shared
			case (short)0x2500:	// change ref data
			case (short)0x2D00: // reset retry counter: activate card and set new PIN
			case (short)0x2D01: // reset retry counter: activate card and reset PIN
				result = true;
			break;
			default: result = false;
		}
		return result;
	}


}