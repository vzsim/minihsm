/***************************************************************************************************
* Module: ECCurves
* Creation Date: 2025/06/19
* Applet Version: V001
* Comment: xxxxxxx
*
****************************************************************************************************
* Copyright © 2025 Intergalaxy Ltd
* All rights reserved
***************************************************************************************************/

package com.vzsim.minihsm;

import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public final class ECCurves {
	
    public static final byte EC_BrainpoolP256r1 = (byte) 0x20;
    public static final byte EC_SEC_P256R1 = (byte) 0x21;
    public static final byte EC_BrainpoolP256t1 = (byte) 0x23;
    public static final byte EC_SecP256k1 = (byte) 0x24;
    public static final byte EC_Frp256v1 = (byte) 0x26;
    
    
    public static final short SW_INCORRECT_ALG = (short)0x6A02;
    public static final short SW_CRYPTO_EXC_BASE_10 = (short)0x6200;
    public static final short ZERO = (short)0;


    static BrainpoolP256r1 brainpoolP256r1; // RSP
    static BrainpoolP256t1 brainpoolP256t1;
    static SecP256k1 secP256k1; // Kolbitz curve (NOT NIST)
    static Frp256v1 frp256v1; // RSP
    static SecP256r1 secP256r1; // RSP

    /**
     * @param nEccCurve
     * @param keyLength
     * @return
     */
    @SuppressWarnings("deprecation")
	public static KeyPair getKeyPair(byte nEccCurve) {
        EcCurvesBase obj = null;

        switch (nEccCurve) {
        case EC_BrainpoolP256r1:
            if (brainpoolP256r1 == null) {
                brainpoolP256r1 = new BrainpoolP256r1();
            }
            obj = brainpoolP256r1;
            break;
        case EC_SEC_P256R1:
            if (secP256r1 == null) {
                secP256r1 = new SecP256r1();
            }
            obj = secP256r1;
            break;
        case EC_BrainpoolP256t1:
            if (brainpoolP256t1 == null) {
                brainpoolP256t1 = new BrainpoolP256t1();
            }
            obj = brainpoolP256t1;
            break;
        case EC_SecP256k1:
            if (secP256k1 == null) {
                secP256k1 = new SecP256k1();
            }
            obj = secP256k1;
            break;
        case EC_Frp256v1:
            if (frp256v1 == null) {
                frp256v1 = new Frp256v1();
            }
            obj = frp256v1;

            break;
        default:
            ISOException.throwIt(SW_INCORRECT_ALG);
        }
        return obj.newKeyPair();
    }

    public static abstract class EcCurvesBase {
        /** Cofactor */
        static final short h = 1;

        /**
         * @return p - the prime.
         */
        protected abstract byte[] getFp();

        /**
         * @return a - the first coefficient of this elliptic curve.
         */
        protected abstract byte[] getA();

        /**
         * @return b - the second coefficient of this elliptic curve.
         */
        protected abstract byte[] getB();

        /**
         * the Generator Point (uncompressed)
         * 
         * @return 04 || the affine x-coordinate. || the affine y-coordinate.
         */
        protected abstract byte[] getG();

        /**
         * the Order of the Generator Point
         * 
         * @return n - the order of the generator g.
         */
        protected abstract byte[] getN();

        /**
         * @return Cofactor
         */
        protected short getK() {
            return h;
        }

        public KeyPair newKeyPair() {
            KeyPair keyPair = null;
            ECPublicKey pubKey = null;
            ECPrivateKey privKey = null;

            byte[] buf = this.getFp();

            short len = (short) ((buf.length - (buf[0] == 0 ? 1 : 0)) * 8);

            pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, len, false);

            short sw12 = setupEccCurve(pubKey);

            if (sw12 == 0) {
                privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, len, false);

                // doesn't appear to support transient private keys
                // eccPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256,
                // false);
                sw12 = this.setupEccCurve(privKey);
            }
            if (sw12 == 0) {
                keyPair = new KeyPair(pubKey, privKey);
            }
            return keyPair;
        }

        private final short setupEccCurve(ECKey key) {
            short sw12 = 0;
            try {
                key.setA(getA(), ZERO, (short) getA().length);
                key.setB(getB(), ZERO, (short) getB().length);
                key.setG(getG(), ZERO, (short) getG().length);
                key.setR(getN(), ZERO, (short) getN().length); /* order of G */
                key.setFieldFP(getFp(), ZERO, (short) getFp().length);
                key.setK(h); // not always needed

            } catch (CryptoException e) {
                sw12 = (short) (SW_CRYPTO_EXC_BASE_10 | e.getReason());
                ISOException.throwIt(sw12);
            }
            return sw12;
        }

    }

    public static class BrainpoolP256t1 extends EcCurvesBase {

        private final static byte[] q = { (byte) 0xa9, (byte) 0xfb, (byte) 0x57, (byte) 0xdb, (byte) 0xa1, (byte) 0xee, (byte) 0xa9, (byte) 0xbc,
                (byte) 0x3e, (byte) 0x66, (byte) 0x0a, (byte) 0x90, (byte) 0x9d, (byte) 0x83, (byte) 0x8d, (byte) 0x72, (byte) 0x6e, (byte) 0x3b,
                (byte) 0xf6, (byte) 0x23, (byte) 0xd5, (byte) 0x26, (byte) 0x20, (byte) 0x28, (byte) 0x20, (byte) 0x13, (byte) 0x48, (byte) 0x1d,
                (byte) 0x1f, (byte) 0x6e, (byte) 0x53, (byte) 0x77 };

        private final static byte[] a = { (byte) 0xa9, (byte) 0xfb, (byte) 0x57, (byte) 0xdb, (byte) 0xa1, (byte) 0xee, (byte) 0xa9, (byte) 0xbc,
                (byte) 0x3e, (byte) 0x66, (byte) 0x0a, (byte) 0x90, (byte) 0x9d, (byte) 0x83, (byte) 0x8d, (byte) 0x72, (byte) 0x6e, (byte) 0x3b,
                (byte) 0xf6, (byte) 0x23, (byte) 0xd5, (byte) 0x26, (byte) 0x20, (byte) 0x28, (byte) 0x20, (byte) 0x13, (byte) 0x48, (byte) 0x1d,
                (byte) 0x1f, (byte) 0x6e, (byte) 0x53, (byte) 0x74 };

        private final static byte[] b = { (byte) 0x66, (byte) 0x2c, (byte) 0x61, (byte) 0xc4, (byte) 0x30, (byte) 0xd8, (byte) 0x4e, (byte) 0xa4,
                (byte) 0xfe, (byte) 0x66, (byte) 0xa7, (byte) 0x73, (byte) 0x3d, (byte) 0x0b, (byte) 0x76, (byte) 0xb7, (byte) 0xbf, (byte) 0x93,
                (byte) 0xeb, (byte) 0xc4, (byte) 0xaf, (byte) 0x2f, (byte) 0x49, (byte) 0x25, (byte) 0x6a, (byte) 0xe5, (byte) 0x81, (byte) 0x01,
                (byte) 0xfe, (byte) 0xe9, (byte) 0x2b, (byte) 0x04 };

        private final static byte[] G = { (byte) 0x04, (byte) 0xa3, (byte) 0xe8, (byte) 0xeb, (byte) 0x3c, (byte) 0xc1, (byte) 0xcf, (byte) 0xe7,
                (byte) 0xb7, (byte) 0x73, (byte) 0x22, (byte) 0x13, (byte) 0xb2, (byte) 0x3a, (byte) 0x65, (byte) 0x61, (byte) 0x49, (byte) 0xaf,
                (byte) 0xa1, (byte) 0x42, (byte) 0xc4, (byte) 0x7a, (byte) 0xaf, (byte) 0xbc, (byte) 0x2b, (byte) 0x79, (byte) 0xa1, (byte) 0x91,
                (byte) 0x56, (byte) 0x2e, (byte) 0x13, (byte) 0x05, (byte) 0xf4, (byte) 0x2d, (byte) 0x99, (byte) 0x6c, (byte) 0x82, (byte) 0x34,
                (byte) 0x39, (byte) 0xc5, (byte) 0x6d, (byte) 0x7f, (byte) 0x7b, (byte) 0x22, (byte) 0xe1, (byte) 0x46, (byte) 0x44, (byte) 0x41,
                (byte) 0x7e, (byte) 0x69, (byte) 0xbc, (byte) 0xb6, (byte) 0xde, (byte) 0x39, (byte) 0xd0, (byte) 0x27, (byte) 0x00, (byte) 0x1d,
                (byte) 0xab, (byte) 0xe8, (byte) 0xf3, (byte) 0x5b, (byte) 0x25, (byte) 0xc9, (byte) 0xbe };

        private final static byte[] r = { (byte) 0xa9, (byte) 0xfb, (byte) 0x57, (byte) 0xdb, (byte) 0xa1, (byte) 0xee, (byte) 0xa9, (byte) 0xbc,
                (byte) 0x3e, (byte) 0x66, (byte) 0x0a, (byte) 0x90, (byte) 0x9d, (byte) 0x83, (byte) 0x8d, (byte) 0x71, (byte) 0x8c, (byte) 0x39,
                (byte) 0x7a, (byte) 0xa3, (byte) 0xb5, (byte) 0x61, (byte) 0xa6, (byte) 0xf7, (byte) 0x90, (byte) 0x1e, (byte) 0x0e, (byte) 0x82,
                (byte) 0x97, (byte) 0x48, (byte) 0x56, (byte) 0xa7 };

        protected final byte[] getFp() {
            return q;
        }

        protected final byte[] getA() {
            return a;
        }

        protected final byte[] getB() {
            return b;
        }

        protected final byte[] getG() {
            return G;
        }

        protected final byte[] getN() {
            return r;
        }

    }

    public static class BrainpoolP256r1 extends EcCurvesBase {

        private final static byte[] q = { (byte) 0xa9, (byte) 0xfb, (byte) 0x57, (byte) 0xdb, (byte) 0xa1, (byte) 0xee, (byte) 0xa9, (byte) 0xbc,
                (byte) 0x3e, (byte) 0x66, (byte) 0x0a, (byte) 0x90, (byte) 0x9d, (byte) 0x83, (byte) 0x8d, (byte) 0x72, (byte) 0x6e, (byte) 0x3b,
                (byte) 0xf6, (byte) 0x23, (byte) 0xd5, (byte) 0x26, (byte) 0x20, (byte) 0x28, (byte) 0x20, (byte) 0x13, (byte) 0x48, (byte) 0x1d,
                (byte) 0x1f, (byte) 0x6e, (byte) 0x53, (byte) 0x77 };

        private final static byte[] a = { (byte) 0x7d, (byte) 0x5a, (byte) 0x09, (byte) 0x75, (byte) 0xfc, (byte) 0x2c, (byte) 0x30, (byte) 0x57,
                (byte) 0xee, (byte) 0xf6, (byte) 0x75, (byte) 0x30, (byte) 0x41, (byte) 0x7a, (byte) 0xff, (byte) 0xe7, (byte) 0xfb, (byte) 0x80,
                (byte) 0x55, (byte) 0xc1, (byte) 0x26, (byte) 0xdc, (byte) 0x5c, (byte) 0x6c, (byte) 0xe9, (byte) 0x4a, (byte) 0x4b, (byte) 0x44,
                (byte) 0xf3, (byte) 0x30, (byte) 0xb5, (byte) 0xd9 };

        private final static byte[] b = { (byte) 0x26, (byte) 0xdc, (byte) 0x5c, (byte) 0x6c, (byte) 0xe9, (byte) 0x4a, (byte) 0x4b, (byte) 0x44,
                (byte) 0xf3, (byte) 0x30, (byte) 0xb5, (byte) 0xd9, (byte) 0xbb, (byte) 0xd7, (byte) 0x7c, (byte) 0xbf, (byte) 0x95, (byte) 0x84,
                (byte) 0x16, (byte) 0x29, (byte) 0x5c, (byte) 0xf7, (byte) 0xe1, (byte) 0xce, (byte) 0x6b, (byte) 0xcc, (byte) 0xdc, (byte) 0x18,
                (byte) 0xff, (byte) 0x8c, (byte) 0x07, (byte) 0xb6 };

        private final static byte[] G = { (byte) 0x04, (byte) 0x8b, (byte) 0xd2, (byte) 0xae, (byte) 0xb9, (byte) 0xcb, (byte) 0x7e, (byte) 0x57,
                (byte) 0xcb, (byte) 0x2c, (byte) 0x4b, (byte) 0x48, (byte) 0x2f, (byte) 0xfc, (byte) 0x81, (byte) 0xb7, (byte) 0xaf, (byte) 0xb9,
                (byte) 0xde, (byte) 0x27, (byte) 0xe1, (byte) 0xe3, (byte) 0xbd, (byte) 0x23, (byte) 0xc2, (byte) 0x3a, (byte) 0x44, (byte) 0x53,
                (byte) 0xbd, (byte) 0x9a, (byte) 0xce, (byte) 0x32, (byte) 0x62, (byte) 0x54, (byte) 0x7e, (byte) 0xf8, (byte) 0x35, (byte) 0xc3,
                (byte) 0xda, (byte) 0xc4, (byte) 0xfd, (byte) 0x97, (byte) 0xf8, (byte) 0x46, (byte) 0x1a, (byte) 0x14, (byte) 0x61, (byte) 0x1d,
                (byte) 0xc9, (byte) 0xc2, (byte) 0x77, (byte) 0x45, (byte) 0x13, (byte) 0x2d, (byte) 0xed, (byte) 0x8e, (byte) 0x54, (byte) 0x5c,
                (byte) 0x1d, (byte) 0x54, (byte) 0xc7, (byte) 0x2f, (byte) 0x04, (byte) 0x69, (byte) 0x97 };

        private final static byte[] r = { (byte) 0xa9, (byte) 0xfb, (byte) 0x57, (byte) 0xdb, (byte) 0xa1, (byte) 0xee, (byte) 0xa9, (byte) 0xbc,
                (byte) 0x3e, (byte) 0x66, (byte) 0x0a, (byte) 0x90, (byte) 0x9d, (byte) 0x83, (byte) 0x8d, (byte) 0x71, (byte) 0x8c, (byte) 0x39,
                (byte) 0x7a, (byte) 0xa3, (byte) 0xb5, (byte) 0x61, (byte) 0xa6, (byte) 0xf7, (byte) 0x90, (byte) 0x1e, (byte) 0x0e, (byte) 0x82,
                (byte) 0x97, (byte) 0x48, (byte) 0x56, (byte) 0xa7 };

        protected final byte[] getFp() {
            return q;
        }

        protected final byte[] getA() {
            return a;
        }

        protected final byte[] getB() {
            return b;
        }

        protected final byte[] getG() {
            return G;
        }

        protected final byte[] getN() {
            return r;
        }

        protected static boolean setCommonCurveParameters(ECKey key) {
        	try {
        		key.setA(SecP256r1.a, (short)0, (short)SecP256r1.a.length);
        		key.setB(SecP256r1.b, (short)0, (short)SecP256r1.b.length);
        		key.setFieldFP(SecP256r1.q, (short)0, (short)SecP256r1.q.length);
        		key.setG(SecP256r1.G, (short)0, (short)SecP256r1.G.length);
        		key.setR(SecP256r1.r, (short)0, (short)SecP256r1.r.length);
        		key.setK(SecP256r1.h);
        		return true;
        	}
        	catch(Exception e) {
        		return false;
        	}
        }
    }

    public static class SecP256r1 extends EcCurvesBase {

        private final static byte[] q = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

        private final static byte[] a = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc };

        private final static byte[] b = { (byte) 0x5a, (byte) 0xc6, (byte) 0x35, (byte) 0xd8, (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7,
                (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xbc, (byte) 0x65, (byte) 0x1d,
                (byte) 0x06, (byte) 0xb0, (byte) 0xcc, (byte) 0x53, (byte) 0xb0, (byte) 0xf6, (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e,
                (byte) 0x27, (byte) 0xd2, (byte) 0x60, (byte) 0x4b };

        private final static byte[] G = { (byte) 0x04, (byte) 0x6b, (byte) 0x17, (byte) 0xd1, (byte) 0xf2, (byte) 0xe1, (byte) 0x2c, (byte) 0x42,
                (byte) 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, (byte) 0x63, (byte) 0xa4, (byte) 0x40, (byte) 0xf2, (byte) 0x77,
                (byte) 0x03, (byte) 0x7d, (byte) 0x81, (byte) 0x2d, (byte) 0xeb, (byte) 0x33, (byte) 0xa0, (byte) 0xf4, (byte) 0xa1, (byte) 0x39,
                (byte) 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96, (byte) 0x4f, (byte) 0xe3, (byte) 0x42, (byte) 0xe2, (byte) 0xfe,
                (byte) 0x1a, (byte) 0x7f, (byte) 0x9b, (byte) 0x8e, (byte) 0xe7, (byte) 0xeb, (byte) 0x4a, (byte) 0x7c, (byte) 0x0f, (byte) 0x9e,
                (byte) 0x16, (byte) 0x2b, (byte) 0xce, (byte) 0x33, (byte) 0x57, (byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce, (byte) 0xcb,
                (byte) 0xb6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xbf, (byte) 0x51, (byte) 0xf5 };

        private final static byte[] r = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xbc, (byte) 0xe6,
                (byte) 0xfa, (byte) 0xad, (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2,
                (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51 };

        protected final byte[] getFp() {
            return q;
        }

        protected final byte[] getA() {
            return a;
        }

        protected final byte[] getB() {
            return b;
        }

        protected final byte[] getG() {
            return G;
        }

        protected final byte[] getN() {
            return r;
        }
        protected static boolean setCommonCurveParameters(ECKey key) {
        	try {
        		key.setA(SecP256r1.a, (short)0, (short)SecP256r1.a.length);
        		key.setB(SecP256r1.b, (short)0, (short)SecP256r1.b.length);
        		key.setFieldFP(SecP256r1.q, (short)0, (short)SecP256r1.q.length);
        		key.setG(SecP256r1.G, (short)0, (short)SecP256r1.G.length);
        		key.setR(SecP256r1.r, (short)0, (short)SecP256r1.r.length);
        		key.setK(SecP256r1.h);
        		return true;
        	}
        	catch(Exception e) {
        		return false;
        	}
        }
    }

    public static class SecP256k1 extends EcCurvesBase {

        private final static byte[] q = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
                (byte) 0xff, (byte) 0xff, (byte) 0xfc, (byte) 0x2f };

        private final static byte[] a = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

        private final static byte[] b = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07 };

        private final static byte[] G = { // 65 bytes
                (byte) 0x04, (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e, (byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac, (byte) 0x55,
                (byte) 0xa0, (byte) 0x62, (byte) 0x95, (byte) 0xce, (byte) 0x87, (byte) 0x0b, (byte) 0x07, (byte) 0x02, (byte) 0x9b, (byte) 0xfc,
                (byte) 0xdb, (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9, (byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b, (byte) 0x16,
                (byte) 0xf8, (byte) 0x17, (byte) 0x98, (byte) 0x48, (byte) 0x3a, (byte) 0xda, (byte) 0x77, (byte) 0x26, (byte) 0xa3, (byte) 0xc4,
                (byte) 0x65, (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc, (byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8, (byte) 0xfd,
                (byte) 0x17, (byte) 0xb4, (byte) 0x48, (byte) 0xa6, (byte) 0x85, (byte) 0x54, (byte) 0x19, (byte) 0x9c, (byte) 0x47, (byte) 0xd0,
                (byte) 0x8f, (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8 };

        private final static byte[] r = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xba, (byte) 0xae,
                (byte) 0xdc, (byte) 0xe6, (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b, (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c,
                (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

        protected final byte[] getFp() {
            return q;
        }

        protected final byte[] getA() {
            return a;
        }

        protected final byte[] getB() {
            return b;
        }

        protected final byte[] getG() {
            return G;
        }

        protected final byte[] getN() {
            return r;
        }

    }

    public static class Frp256v1 extends EcCurvesBase {

        private final static byte[] q = { (byte) 0xf1, (byte) 0xfd, (byte) 0x17, (byte) 0x8c, (byte) 0x0b, (byte) 0x3a, (byte) 0xd5, (byte) 0x8f,
                (byte) 0x10, (byte) 0x12, (byte) 0x6d, (byte) 0xe8, (byte) 0xce, (byte) 0x42, (byte) 0x43, (byte) 0x5b, (byte) 0x39, (byte) 0x61,
                (byte) 0xad, (byte) 0xbc, (byte) 0xab, (byte) 0xc8, (byte) 0xca, (byte) 0x6d, (byte) 0xe8, (byte) 0xfc, (byte) 0xf3, (byte) 0x53,
                (byte) 0xd8, (byte) 0x6e, (byte) 0x9c, (byte) 0x03 };

        private final static byte[] a = { (byte) 0xf1, (byte) 0xfd, (byte) 0x17, (byte) 0x8c, (byte) 0x0b, (byte) 0x3a, (byte) 0xd5, (byte) 0x8f,
                (byte) 0x10, (byte) 0x12, (byte) 0x6d, (byte) 0xe8, (byte) 0xce, (byte) 0x42, (byte) 0x43, (byte) 0x5b, (byte) 0x39, (byte) 0x61,
                (byte) 0xad, (byte) 0xbc, (byte) 0xab, (byte) 0xc8, (byte) 0xca, (byte) 0x6d, (byte) 0xe8, (byte) 0xfc, (byte) 0xf3, (byte) 0x53,
                (byte) 0xd8, (byte) 0x6e, (byte) 0x9c, (byte) 0x00 };

        private final static byte[] b = { (byte) 0xee, (byte) 0x35, (byte) 0x3f, (byte) 0xca, (byte) 0x54, (byte) 0x28, (byte) 0xa9, (byte) 0x30,
                (byte) 0x0d, (byte) 0x4a, (byte) 0xba, (byte) 0x75, (byte) 0x4a, (byte) 0x44, (byte) 0xc0, (byte) 0x0f, (byte) 0xdf, (byte) 0xec,
                (byte) 0x0c, (byte) 0x9a, (byte) 0xe4, (byte) 0xb1, (byte) 0xa1, (byte) 0x80, (byte) 0x30, (byte) 0x75, (byte) 0xed, (byte) 0x96,
                (byte) 0x7b, (byte) 0x7b, (byte) 0xb7, (byte) 0x3f };

        private final static byte[] G = { (byte) 0x04, (byte) 0xb6, (byte) 0xb3, (byte) 0xd4, (byte) 0xc3, (byte) 0x56, (byte) 0xc1, (byte) 0x39,
                (byte) 0xeb, (byte) 0x31, (byte) 0x18, (byte) 0x3d, (byte) 0x47, (byte) 0x49, (byte) 0xd4, (byte) 0x23, (byte) 0x95, (byte) 0x8c,
                (byte) 0x27, (byte) 0xd2, (byte) 0xdc, (byte) 0xaf, (byte) 0x98, (byte) 0xb7, (byte) 0x01, (byte) 0x64, (byte) 0xc9, (byte) 0x7a,
                (byte) 0x2d, (byte) 0xd9, (byte) 0x8f, (byte) 0x5c, (byte) 0xff, (byte) 0x61, (byte) 0x42, (byte) 0xe0, (byte) 0xf7, (byte) 0xc8,
                (byte) 0xb2, (byte) 0x04, (byte) 0x91, (byte) 0x1f, (byte) 0x92, (byte) 0x71, (byte) 0xf0, (byte) 0xf3, (byte) 0xec, (byte) 0xef,
                (byte) 0x8c, (byte) 0x27, (byte) 0x01, (byte) 0xc3, (byte) 0x07, (byte) 0xe8, (byte) 0xe4, (byte) 0xc9, (byte) 0xe1, (byte) 0x83,
                (byte) 0x11, (byte) 0x5a, (byte) 0x15, (byte) 0x54, (byte) 0x06, (byte) 0x2c, (byte) 0xfb };

        private final static byte[] r = { (byte) 0xF1, (byte) 0xFD, (byte) 0x17, (byte) 0x8C, (byte) 0x0B, (byte) 0x3A, (byte) 0xD5, (byte) 0x8F,
                (byte) 0x10, (byte) 0x12, (byte) 0x6D, (byte) 0xE8, (byte) 0xCE, (byte) 0x42, (byte) 0x43, (byte) 0x5B, (byte) 0x53, (byte) 0xDC,
                (byte) 0x67, (byte) 0xE1, (byte) 0x40, (byte) 0xD2, (byte) 0xBF, (byte) 0x94, (byte) 0x1F, (byte) 0xFD, (byte) 0xD4, (byte) 0x59,
                (byte) 0xC6, (byte) 0xD6, (byte) 0x55, (byte) 0xE1 };

        protected final byte[] getFp() {
            return q;
        }

        protected final byte[] getA() {
            return a;
        }

        protected final byte[] getB() {
            return b;
        }

        protected final byte[] getG() {
            return G;
        }

        protected final byte[] getN() {
            return r;
        }

    }

}
