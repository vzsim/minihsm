package com.vzsim.minihsm;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;


public class CryptoKey extends Applet implements ISO7816
{
	private static final short SW_PIN_TRIES_REMAINING      = (short)0x63C0; // See ISO 7816-4 section 7.5.1
	private static final short SW_ARRAY_INDEX_OUT_OF_RANGE = (short)0x6703;

	/* Constant values */
	private static final byte INS_VERIFY                = (byte)0x20;
    private static final byte INS_CHANGE_REFERENCE_DATA = (byte)0x25;
	private static final byte INS_RESET_RETRY_COUNTER   = (byte)0x2D;
	private static final byte INS_OPEN_SM_SESSION       = (byte)0x80;
	private static final byte INS_GET_DATA				= (byte)0xCA;

	private static final byte PIN_MAX_TRIES             = (byte)0x03;
	private static final byte PUK_MAX_TRIES             = (byte)0x0A;
	private static final byte PIN_MIN_LENGTH            = (byte)0x04;
	private static final byte PIN_MAX_LENGTH            = (byte)0x10;
	
	private static final short APPLET_STATE_OFFSET_SM   = (short)0x01;
	private static final short APPLET_STATE_OFFSET_LCS  = (short)0x00;
	
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
		(byte)0x0B, (byte)'I', (byte)'n', (byte)'t', (byte)'e', (byte)'r', (byte)'G', (byte)'a', (byte)'l', (byte)'a', (byte)'x', (byte)'y'
	};
	
	/** "MiniHSM" */
	private static final byte[] MODEL = {
		(byte)0x04, (byte)'e', (byte)'S', (byte)'I', (byte)'M'
	};

	/** 31121985 */
	private static final byte[] SERIAL_NUMBER = {
		(byte)0x08, (byte)'3', (byte)'1', (byte)'1', (byte)'2',(byte)'1', (byte)'9', (byte)'8', (byte)'5'
	};

	private byte[]   appletState = null;
	private OwnerPIN pin         = null;
	private OwnerPIN puk         = null;
	private byte[]   TOKEN_LABEL = null;

	private KeyPair ecF2MPair             = null;
	private ECPrivateKey ecF2MprivKey     = null;
	private ECPublicKey  ecF2MpubKey      = null;
	private KeyAgreement ecSvdpDhKeyAgrmt = null;
	private byte[] sharedSecret             = null;

	public
	CryptoKey()
	{
		puk = new OwnerPIN(PUK_MAX_TRIES, PIN_MAX_LENGTH);
		pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);

		ecF2MPair = new KeyPair(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_163);
		ecF2MPair.genKeyPair();
		
		ecF2MprivKey = (ECPrivateKey)ecF2MPair.getPrivate();
		ecF2MpubKey  = (ECPublicKey)ecF2MPair.getPublic();

		/*
			KeyAgreement.ALG_EC_SVDP_DH
			KeyAgreement.ALG_EC_SVDP_DH_KDF
			KeyAgreement.ALG_EC_SVDP_DH_PLAIN
			
			KeyAgreement.ALG_EC_SVDP_DHC
			KeyAgreement.ALG_EC_SVDP_DHC_KDF
			KeyAgreement.ALG_EC_SVDP_DHC_PLAIN
		 */
		ecSvdpDhKeyAgrmt = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		ecSvdpDhKeyAgrmt.init(ecF2MprivKey);
		sharedSecret = JCSystem.makeTransientByteArray((short)20, JCSystem.CLEAR_ON_DESELECT);
		TOKEN_LABEL = new byte[33];
		TOKEN_LABEL[0] = (byte)0;
		appletState = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_RESET);

		appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_CREATION;
		appletState[APPLET_STATE_OFFSET_SM] = ~SM_STATE_ESTABLISHED;
	}

	public static void
	install(byte[] bArray, short bOffset, byte bLength)
	{
		new CryptoKey().register();
	}
	
	public void
	process(APDU apdu) throws ISOException
	{
		if (selectingApplet()) {
			appletState[APPLET_STATE_OFFSET_SM] = ~SM_STATE_ESTABLISHED;
			return;
		}

		byte[] buff = apdu.getBuffer();
		byte ins = buff[OFFSET_INS];

		if (appletState[APPLET_STATE_OFFSET_LCS] == APP_STATE_TERMINATED) {
			ISOException.throwIt((short)(SW_UNKNOWN | APP_STATE_TERMINATED));
		}
		
		try {
			switch (ins) {
				case INS_CHANGE_REFERENCE_DATA: {
					changeReferenceData(apdu);
				} break;
				case INS_VERIFY: {
					verify(apdu);
				} break;
				case INS_RESET_RETRY_COUNTER: {
					resetRetryCounter(apdu);
				} break;
				case INS_OPEN_SM_SESSION: {
					openSecureMessagingSession(apdu);
				} break;
				case INS_GET_DATA: {
					getData(apdu);
				} break;
				default: {
					ISOException.throwIt(SW_ARRAY_INDEX_OUT_OF_RANGE);
				}
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			ISOException.throwIt(SW_DATA_INVALID);
		}
	}

	/**
	 * CHANGE REFERENCE DATA (INS 0X25), ISO 7816-4, clause 11.5.7.
	 * 
	 * CDATA shall contain BER-TLV data object (ISO 7816-4, clause 6.3) to make it possible to
	 * distinguish one type of data from another (i.e. current PIN and new PIN).
	 * 
	 * This method handles the following data at specific Life cycle states:
	 * 
	 * LCS							CDATA
	 * APP_STATE_CREATION			[81 Len <Initial PUK bytes>]
	 * APP_STATE_INITIALIZATION		[81 Len <Initial PIN bytes>]
	 * APP_STATE_ACTIVATED			[81 Len <CURR PIN bytes> 82 Len <NEW PIN bytes>]
	 * @param apdu
	 */
	private void
	changeReferenceData(APDU apdu)
	{
		byte[] buff = apdu.getBuffer();
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];

		short cdataOff, lc, len = 0, off = 0;

		lc = apdu.setIncomingAndReceive();
		if (lc == (short)0 || lc != apdu.getIncomingLength()) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		cdataOff = apdu.getOffsetCdata();

		// Common case for each LCS: either PIN or PUK.
		len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x81);
		off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x81);

		if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		
		switch (appletState[APPLET_STATE_OFFSET_LCS]) {

			case APP_STATE_CREATION: {	// Set PUK

				if (p2 != (byte)0x01 && p2 != (byte)0x02) {
					ISOException.throwIt(SW_INCORRECT_P1P2);
				}

				puk.update(buff, off, (byte)len);
				puk.resetAndUnblock();
				
				len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x82);
				off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x82);
				
				// (off - 1) grab the length too.
				Util.arrayCopyNonAtomic(buff, (short)(off - (short)1), TOKEN_LABEL, (short)0, (short)(len + (short)1));
				appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_INITIALIZATION;

			} break;
			case APP_STATE_INITIALIZATION: {	// Set PIN

				if (p1 != (byte)0x01 || p2 != (byte)0x01) {
					ISOException.throwIt(SW_INCORRECT_P1P2);
				}

				pin.update(buff, off, (byte)len);
				pin.resetAndUnblock();

				appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_ACTIVATED;
				
			} break;
			case APP_STATE_ACTIVATED: {	// Update PIN

				if (p1 != (byte)0x00 || p2 != (byte)0x00) {
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
	}

	/**
	 * VERIFY (INS 0X20), ISO 7816-4, clause 11.5.6.
	 * @param apdu
	 */
	private void
	verify(APDU apdu)
	{
		byte[] buff = apdu.getBuffer();
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];

		short cdataOff, lc;
		byte appState = appletState[APPLET_STATE_OFFSET_LCS];

		if (appState == APP_STATE_DEACTIVATED) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		if (p1 != (byte)0x00 || p2 != (byte)0x01) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		
		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())  {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		
		cdataOff = apdu.getOffsetCdata();

		// At the below mentioned states no PIN is set yet, thus there is no error at all.
		if (lc == (byte)0x00 && (appState == APP_STATE_CREATION || appState == APP_STATE_INITIALIZATION)) {
			
			ISOException.throwIt(SW_NO_ERROR);

		} else if (lc == (byte)0x00 && (appState == APP_STATE_ACTIVATED)) {

			// Absence of CDATA means that user requested the number of remaining tries.
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		}

		if (lc < PIN_MIN_LENGTH || lc > PIN_MAX_LENGTH) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		// Check the PIN.
		if (!pin.check(buff, cdataOff, (byte)lc)) {

			if (pin.getTriesRemaining() < (byte)1) {
				appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_DEACTIVATED;
			}

			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		}
	}

	/**
	 * RESET RETRY COUNTER (INS 0X2D), ISO 7816-4, clause 11.5.10.
	 * Supported combinations are:
	 * P1 == 0 CDATA: [81 Len PUK && 82 Len NEW PIN] // appying new PIN
	 * P1 == 1 CDATA: [81 Len PUK]					 // Just reset PIN tries counter
	 * P3 == 3 CDATA: absent						 // get PUK remaining tries
	 * @param apdu
	 */
	private void
	resetRetryCounter(APDU apdu)
	{
		byte[] buff = apdu.getBuffer();
		byte p1 = buff[OFFSET_P1];
		byte p2 = buff[OFFSET_P2];
		short cdataOff, lc, len, off;

		if (appletState[APPLET_STATE_OFFSET_LCS] != APP_STATE_DEACTIVATED || puk == null) {
			ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
		}

		if ((p1 == (byte)0x02 || p1 > (byte)0x03) || p2 != (byte)0x01) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		cdataOff = apdu.getOffsetCdata();

		// User requested PUK tries counter only.
		if (p1 == (byte)0x03) {
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
		}

		// Common case for P1=0 and P1=1: retrieving PUK
		len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x81);
		off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x81);

		if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
			ISOException.throwIt(SW_WRONG_DATA);
		}

		if (!puk.check(buff, off, (byte)len)) {
			if (puk.getTriesRemaining() < (byte)1) {
				appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_TERMINATED;
			}
			ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
		}

		// P1=0: retrieve and apply a new PIN value.
		if (p1 == (byte)0x00) {
			
			off = UtilTLV.tlvGetValue(buff, cdataOff, lc, (byte)0x82);
			len = UtilTLV.tlvGetLen(buff, cdataOff, lc, (byte)0x82);

			if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || off == (short)-1) {
				ISOException.throwIt(SW_WRONG_DATA);
			}

			pin.update(buff, off, (byte)len);
		}

		// Committing commmon case for P1=0 and P1=1: reset and unblock PIN
		pin.resetAndUnblock();
		appletState[APPLET_STATE_OFFSET_LCS] = APP_STATE_ACTIVATED;
	}
	

	private void
	openSecureMessagingSession(APDU apdu)
	{
		short cdataOff = 0, lc = 0, offset = 0;
		byte[] buf = apdu.getBuffer();
		
		lc = apdu.setIncomingAndReceive();
		if ((lc != apdu.getIncomingLength()) || (lc != (short)20)) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		cdataOff = apdu.getOffsetCdata();

		lc = ecSvdpDhKeyAgrmt.generateSecret(buf, cdataOff, lc, sharedSecret, (short)0);
		offset = Util.arrayCopyNonAtomic(sharedSecret, (short)0, buf, offset, lc);

		lc += ecF2MpubKey.getW(buf, offset);
		apdu.setOutgoingAndSend((short)0, lc);
	}

	/**
	 * GET DATA apdu (INS = CA), ISO 7816-4, clause 11.4.3.
	 * Available values:
	 * P1P2 == 00FF: retrieve all data
	 */
	private void
	getData(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		short p1p2  = (short)((short)buf[OFFSET_P1] << (short)8);
		      p1p2 |= (short)((short)buf[OFFSET_P2] & (short)0x00FF);

		short offset = OFFSET_CDATA;

		switch (p1p2) {
			case (short)0x00FF: {
				buf[offset++] = appletState[APPLET_STATE_OFFSET_LCS];
				buf[offset++] = API_VERSION_MAJOR;
				buf[offset++] = API_VERSION_MINOR;
				buf[offset++] = PIN_MIN_LENGTH;
				buf[offset++] = PIN_MAX_LENGTH;

				offset = Util.arrayCopyNonAtomic(MANUFACTURER,  (short)0, buf, offset, (short)((short)MANUFACTURER[0]  + (short)1));
				offset = Util.arrayCopyNonAtomic(TOKEN_LABEL,   (short)0, buf, offset, (short)((short)TOKEN_LABEL[0]   + (short)1));
				offset = Util.arrayCopyNonAtomic(MODEL,         (short)0, buf, offset, (short)((short)MODEL[0]         + (short)1));
				offset = Util.arrayCopyNonAtomic(SERIAL_NUMBER, (short)0, buf, offset, (short)((short)SERIAL_NUMBER[0] + (short)1));

			} break;
			default: ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		apdu.setOutgoingAndSend((short)OFFSET_CDATA, (short)(offset - OFFSET_CDATA));
	}
}