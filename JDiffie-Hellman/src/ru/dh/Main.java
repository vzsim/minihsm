package ru.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.ECGenParameterSpec;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.Arrays;

public class Main
{
	protected static DiffieHellman dh = null;
	protected static PCSC pcsc = null;

	public static byte[]
	getCardsPublicKey() throws CardException
	{
		
		ResponseAPDU r = pcsc.channel.transmit(new CommandAPDU(new byte[]{(byte)0x00 ,(byte)0xA4 ,(byte)0x04 ,(byte)0x00 ,(byte)0x06 ,(byte)0xA0 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00 ,(byte)0x01 ,(byte)0x01 ,(byte)0x00}));
		r = pcsc.channel.transmit(new CommandAPDU(new byte[]{(byte)0x00 ,(byte)0x80 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00}));
		
		byte[] cardPub = Arrays.copyOfRange(r.getBytes(), 1, r.getBytes().length);
		cardPub = Arrays.copyOfRange(cardPub, 0, cardPub.length - 2);

		return cardPub;
	}

	public static byte[]
	getCardsSessionKey(byte[] alicePub) throws CardException
	{
		alicePub = Arrays.copyOfRange(alicePub, 1, alicePub.length);
		byte[] cmd = new byte[5 + alicePub.length];
		System.arraycopy(new byte[]{(byte)0x00 ,(byte)0x80 ,(byte)0x01 ,(byte)0x00 ,(byte)alicePub.length}, 0, cmd, 0, 5);
		System.arraycopy(alicePub, 0, cmd, 5, alicePub.length);

		ResponseAPDU response = pcsc.channel.transmit(new CommandAPDU(cmd));

		pcsc.card.disconnect(false);
		return response.getBytes();
	}

	public static void
	main(String[] args) throws Exception
	{
		
		
		try {
			pcsc = new PCSC();
			pcsc.connectCard();

			dh = new DiffieHellman(new BouncyCastleProvider(), "ECDH", "BC", "prime256v1");
			KeyPair Alice = dh.kpGen.generateKeyPair();
			// KeyPair Bob = dh.kpGen.generateKeyPair();

			// System.out.println("Alice: " + Alice.getPrivate() + "\n");
			// System.out.println("Alice pub: " + Alice.getPublic());
			// System.out.println("Bob:   " + Bob.getPrivate() + "\n");
			// System.out.println("Bob pub:   " + Bob.getPublic());

			byte[] prvAlice = dh.savePrivateKey(Alice.getPrivate());
			byte[] pubAlice = dh.savePublicKey(Alice.getPublic());

			// byte[] prvBob = dh.savePrivateKey(Bob.getPrivate());
			// byte[] pubBob = dh.savePublicKey(Bob.getPublic());
			
			System.out.println("Alice Private: " + DiffieHellman.bytesToHexString(prvAlice));
			System.out.println("Alice Public:  " + DiffieHellman.bytesToHexString(pubAlice));

			// System.out.println("Bob Private: " + DiffieHellman.bytesToHexString(prvBob));
			// System.out.println("Bob Public:  " + DiffieHellman.bytesToHexString(pubBob));
			

			byte[] pubBob = getCardsPublicKey();
			dh.generateSessionKey("Alice's secret: ", prvAlice, pubBob);
			// dh.generateSessionKey("Alice's secret: ", prvBob, pubAlice);
			getCardsSessionKey(pubAlice);

			pcsc.disconnectCard();

		} catch (NoSuchAlgorithmException e) {
			System.err.println("No such algo: " + e.getMessage());
		}catch (NoSuchProviderException e) {
			System.err.println("No such provider: " + e.getMessage());
		}catch (InvalidAlgorithmParameterException e) {
			System.err.println("Invalid algorithm paramenter: " + e.getMessage());
		}catch (Exception e) {
			System.err.println("Unhandled exception: " + e.getMessage());
		} finally {
			pcsc.disconnectCard();
		}
	}
}

class DiffieHellman
{
	private String stdName        = null;
	private String algorithm      = null;
	private String provider       = null;
	public KeyPairGenerator kpGen = null;

	public DiffieHellman(Provider providerObj, String algo, String providerStr, String stdN) throws Exception
	{
		stdName   = stdN;
		algorithm = algo;
		provider  = providerStr;

		Security.addProvider(providerObj);
		kpGen = KeyPairGenerator.getInstance(algorithm, provider);
		kpGen.initialize(new ECGenParameterSpec(stdName), new SecureRandom());
	}

	public byte[]
	savePublicKey(PublicKey key)
	{
		ECPublicKey ecKey = (ECPublicKey)key;
		return ecKey.getQ().getEncoded(true);
	}

	public byte[]
	savePrivateKey(PrivateKey key)
	{
		ECPrivateKey ecKey = (ECPrivateKey)key;
		return ecKey.getD().toByteArray();
	}

	public void
	generateSessionKey(String msg, byte[] myPrvKey, byte[] hisPubKey) throws Exception
	{
		KeyAgreement ka = KeyAgreement.getInstance(algorithm, provider);
		ka.init(loadPrivateKey(myPrvKey));
		ka.doPhase(loadPublicKey(hisPubKey), true);

		byte[] secret = ka.generateSecret();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		secret = md.digest(secret);
		System.out.println(msg + bytesToHexString(secret));
	}

	private PublicKey
	loadPublicKey(byte[] data) throws Exception
	{
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(stdName);
		ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePublic(pubKey);
	}

	private PrivateKey
	loadPrivateKey(byte[] data) throws Exception
	{
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(stdName);
		ECPrivateKeySpec prvKey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePrivate(prvKey);
	}

	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	public static String bytesToHexString(byte[] bytes)
	{
		char[] hexChars = new char[bytes.length * 2];

		for (int i = 0; i < bytes.length; ++i) {
			byte v = bytes[i];
			hexChars[i * 2]     = hexArray[(v >>> 4) & 0x0F];
			hexChars[i * 2 + 1] = hexArray[ v        & 0x0F];
		}

		return new String(hexChars);
	}
}

class PCSC
{
	protected CardChannel channel;
	protected Card card;
	protected CardTerminal terminal;

	public PCSC() throws CardException
	{
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals = factory.terminals().list();
		System.out.println("Terminals: " + terminals);

		terminal = terminals.get(0);
		card = terminal.connect("*");
		System.out.println("card: " + card);

		channel = card.getBasicChannel();
	}

	public void connectCard() throws CardException
	{	
		terminal.waitForCardPresent(0);
		card	= terminal.connect("*");
		channel	= card.getBasicChannel();
	}

	public void disconnectCard() throws CardException
	{
		card.disconnect(false);
	}
}