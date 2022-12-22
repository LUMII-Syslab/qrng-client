package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Digest;

/**
 * Base class for Haraka v2, https://eprint.iacr.org/2016/098.pdf
 */
public abstract class HarakaBase
    implements Digest
{
    protected static final int DIGEST_SIZE = 32;

    // Haraka round constants
    static final byte[][] RC = new byte[][]
    {
        new byte[]{ (byte)0x9D, (byte)0x7B, (byte)0x81, (byte)0x75, (byte)0xF0, (byte)0xFE, (byte)0xC5, (byte)0xB2, (byte)0x0A, (byte)0xC0, (byte)0x20, (byte)0xE6, (byte)0x4C, (byte)0x70, (byte)0x84, (byte)0x06 },
        new byte[]{ (byte)0x17, (byte)0xF7, (byte)0x08, (byte)0x2F, (byte)0xA4, (byte)0x6B, (byte)0x0F, (byte)0x64, (byte)0x6B, (byte)0xA0, (byte)0xF3, (byte)0x88, (byte)0xE1, (byte)0xB4, (byte)0x66, (byte)0x8B },
        new byte[]{ (byte)0x14, (byte)0x91, (byte)0x02, (byte)0x9F, (byte)0x60, (byte)0x9D, (byte)0x02, (byte)0xCF, (byte)0x98, (byte)0x84, (byte)0xF2, (byte)0x53, (byte)0x2D, (byte)0xDE, (byte)0x02, (byte)0x34 },
        new byte[]{ (byte)0x79, (byte)0x4F, (byte)0x5B, (byte)0xFD, (byte)0xAF, (byte)0xBC, (byte)0xF3, (byte)0xBB, (byte)0x08, (byte)0x4F, (byte)0x7B, (byte)0x2E, (byte)0xE6, (byte)0xEA, (byte)0xD6, (byte)0x0E },
        new byte[]{ (byte)0x44, (byte)0x70, (byte)0x39, (byte)0xBE, (byte)0x1C, (byte)0xCD, (byte)0xEE, (byte)0x79, (byte)0x8B, (byte)0x44, (byte)0x72, (byte)0x48, (byte)0xCB, (byte)0xB0, (byte)0xCF, (byte)0xCB },
        new byte[]{ (byte)0x7B, (byte)0x05, (byte)0x8A, (byte)0x2B, (byte)0xED, (byte)0x35, (byte)0x53, (byte)0x8D, (byte)0xB7, (byte)0x32, (byte)0x90, (byte)0x6E, (byte)0xEE, (byte)0xCD, (byte)0xEA, (byte)0x7E },
        new byte[]{ (byte)0x1B, (byte)0xEF, (byte)0x4F, (byte)0xDA, (byte)0x61, (byte)0x27, (byte)0x41, (byte)0xE2, (byte)0xD0, (byte)0x7C, (byte)0x2E, (byte)0x5E, (byte)0x43, (byte)0x8F, (byte)0xC2, (byte)0x67 },
        new byte[]{ (byte)0x3B, (byte)0x0B, (byte)0xC7, (byte)0x1F, (byte)0xE2, (byte)0xFD, (byte)0x5F, (byte)0x67, (byte)0x07, (byte)0xCC, (byte)0xCA, (byte)0xAF, (byte)0xB0, (byte)0xD9, (byte)0x24, (byte)0x29 },
        new byte[]{ (byte)0xEE, (byte)0x65, (byte)0xD4, (byte)0xB9, (byte)0xCA, (byte)0x8F, (byte)0xDB, (byte)0xEC, (byte)0xE9, (byte)0x7F, (byte)0x86, (byte)0xE6, (byte)0xF1, (byte)0x63, (byte)0x4D, (byte)0xAB },
        new byte[]{ (byte)0x33, (byte)0x7E, (byte)0x03, (byte)0xAD, (byte)0x4F, (byte)0x40, (byte)0x2A, (byte)0x5B, (byte)0x64, (byte)0xCD, (byte)0xB7, (byte)0xD4, (byte)0x84, (byte)0xBF, (byte)0x30, (byte)0x1C },
        new byte[]{ (byte)0x00, (byte)0x98, (byte)0xF6, (byte)0x8D, (byte)0x2E, (byte)0x8B, (byte)0x02, (byte)0x69, (byte)0xBF, (byte)0x23, (byte)0x17, (byte)0x94, (byte)0xB9, (byte)0x0B, (byte)0xCC, (byte)0xB2 },
        new byte[]{ (byte)0x8A, (byte)0x2D, (byte)0x9D, (byte)0x5C, (byte)0xC8, (byte)0x9E, (byte)0xAA, (byte)0x4A, (byte)0x72, (byte)0x55, (byte)0x6F, (byte)0xDE, (byte)0xA6, (byte)0x78, (byte)0x04, (byte)0xFA },
        new byte[]{ (byte)0xD4, (byte)0x9F, (byte)0x12, (byte)0x29, (byte)0x2E, (byte)0x4F, (byte)0xFA, (byte)0x0E, (byte)0x12, (byte)0x2A, (byte)0x77, (byte)0x6B, (byte)0x2B, (byte)0x9F, (byte)0xB4, (byte)0xDF },
        new byte[]{ (byte)0xEE, (byte)0x12, (byte)0x6A, (byte)0xBB, (byte)0xAE, (byte)0x11, (byte)0xD6, (byte)0x32, (byte)0x36, (byte)0xA2, (byte)0x49, (byte)0xF4, (byte)0x44, (byte)0x03, (byte)0xA1, (byte)0x1E },
        new byte[]{ (byte)0xA6, (byte)0xEC, (byte)0xA8, (byte)0x9C, (byte)0xC9, (byte)0x00, (byte)0x96, (byte)0x5F, (byte)0x84, (byte)0x00, (byte)0x05, (byte)0x4B, (byte)0x88, (byte)0x49, (byte)0x04, (byte)0xAF },
        new byte[]{ (byte)0xEC, (byte)0x93, (byte)0xE5, (byte)0x27, (byte)0xE3, (byte)0xC7, (byte)0xA2, (byte)0x78, (byte)0x4F, (byte)0x9C, (byte)0x19, (byte)0x9D, (byte)0xD8, (byte)0x5E, (byte)0x02, (byte)0x21 },
        new byte[]{ (byte)0x73, (byte)0x01, (byte)0xD4, (byte)0x82, (byte)0xCD, (byte)0x2E, (byte)0x28, (byte)0xB9, (byte)0xB7, (byte)0xC9, (byte)0x59, (byte)0xA7, (byte)0xF8, (byte)0xAA, (byte)0x3A, (byte)0xBF },
        new byte[]{ (byte)0x6B, (byte)0x7D, (byte)0x30, (byte)0x10, (byte)0xD9, (byte)0xEF, (byte)0xF2, (byte)0x37, (byte)0x17, (byte)0xB0, (byte)0x86, (byte)0x61, (byte)0x0D, (byte)0x70, (byte)0x60, (byte)0x62 },
        new byte[]{ (byte)0xC6, (byte)0x9A, (byte)0xFC, (byte)0xF6, (byte)0x53, (byte)0x91, (byte)0xC2, (byte)0x81, (byte)0x43, (byte)0x04, (byte)0x30, (byte)0x21, (byte)0xC2, (byte)0x45, (byte)0xCA, (byte)0x5A },
        new byte[]{ (byte)0x3A, (byte)0x94, (byte)0xD1, (byte)0x36, (byte)0xE8, (byte)0x92, (byte)0xAF, (byte)0x2C, (byte)0xBB, (byte)0x68, (byte)0x6B, (byte)0x22, (byte)0x3C, (byte)0x97, (byte)0x23, (byte)0x92 },
        new byte[]{ (byte)0xB4, (byte)0x71, (byte)0x10, (byte)0xE5, (byte)0x58, (byte)0xB9, (byte)0xBA, (byte)0x6C, (byte)0xEB, (byte)0x86, (byte)0x58, (byte)0x22, (byte)0x38, (byte)0x92, (byte)0xBF, (byte)0xD3 },
        new byte[]{ (byte)0x8D, (byte)0x12, (byte)0xE1, (byte)0x24, (byte)0xDD, (byte)0xFD, (byte)0x3D, (byte)0x93, (byte)0x77, (byte)0xC6, (byte)0xF0, (byte)0xAE, (byte)0xE5, (byte)0x3C, (byte)0x86, (byte)0xDB },
        new byte[]{ (byte)0xB1, (byte)0x12, (byte)0x22, (byte)0xCB, (byte)0xE3, (byte)0x8D, (byte)0xE4, (byte)0x83, (byte)0x9C, (byte)0xA0, (byte)0xEB, (byte)0xFF, (byte)0x68, (byte)0x62, (byte)0x60, (byte)0xBB },
        new byte[]{ (byte)0x7D, (byte)0xF7, (byte)0x2B, (byte)0xC7, (byte)0x4E, (byte)0x1A, (byte)0xB9, (byte)0x2D, (byte)0x9C, (byte)0xD1, (byte)0xE4, (byte)0xE2, (byte)0xDC, (byte)0xD3, (byte)0x4B, (byte)0x73 },
        new byte[]{ (byte)0x4E, (byte)0x92, (byte)0xB3, (byte)0x2C, (byte)0xC4, (byte)0x15, (byte)0x14, (byte)0x4B, (byte)0x43, (byte)0x1B, (byte)0x30, (byte)0x61, (byte)0xC3, (byte)0x47, (byte)0xBB, (byte)0x43 },
        new byte[]{ (byte)0x99, (byte)0x68, (byte)0xEB, (byte)0x16, (byte)0xDD, (byte)0x31, (byte)0xB2, (byte)0x03, (byte)0xF6, (byte)0xEF, (byte)0x07, (byte)0xE7, (byte)0xA8, (byte)0x75, (byte)0xA7, (byte)0xDB },
        new byte[]{ (byte)0x2C, (byte)0x47, (byte)0xCA, (byte)0x7E, (byte)0x02, (byte)0x23, (byte)0x5E, (byte)0x8E, (byte)0x77, (byte)0x59, (byte)0x75, (byte)0x3C, (byte)0x4B, (byte)0x61, (byte)0xF3, (byte)0x6D },
        new byte[]{ (byte)0xF9, (byte)0x17, (byte)0x86, (byte)0xB8, (byte)0xB9, (byte)0xE5, (byte)0x1B, (byte)0x6D, (byte)0x77, (byte)0x7D, (byte)0xDE, (byte)0xD6, (byte)0x17, (byte)0x5A, (byte)0xA7, (byte)0xCD },
        new byte[]{ (byte)0x5D, (byte)0xEE, (byte)0x46, (byte)0xA9, (byte)0x9D, (byte)0x06, (byte)0x6C, (byte)0x9D, (byte)0xAA, (byte)0xE9, (byte)0xA8, (byte)0x6B, (byte)0xF0, (byte)0x43, (byte)0x6B, (byte)0xEC },
        new byte[]{ (byte)0xC1, (byte)0x27, (byte)0xF3, (byte)0x3B, (byte)0x59, (byte)0x11, (byte)0x53, (byte)0xA2, (byte)0x2B, (byte)0x33, (byte)0x57, (byte)0xF9, (byte)0x50, (byte)0x69, (byte)0x1E, (byte)0xCB },
        new byte[]{ (byte)0xD9, (byte)0xD0, (byte)0x0E, (byte)0x60, (byte)0x53, (byte)0x03, (byte)0xED, (byte)0xE4, (byte)0x9C, (byte)0x61, (byte)0xDA, (byte)0x00, (byte)0x75, (byte)0x0C, (byte)0xEE, (byte)0x2C },
        new byte[]{ (byte)0x50, (byte)0xA3, (byte)0xA4, (byte)0x63, (byte)0xBC, (byte)0xBA, (byte)0xBB, (byte)0x80, (byte)0xAB, (byte)0x0C, (byte)0xE9, (byte)0x96, (byte)0xA1, (byte)0xA5, (byte)0xB1, (byte)0xF0 },
        new byte[]{ (byte)0x39, (byte)0xCA, (byte)0x8D, (byte)0x93, (byte)0x30, (byte)0xDE, (byte)0x0D, (byte)0xAB, (byte)0x88, (byte)0x29, (byte)0x96, (byte)0x5E, (byte)0x02, (byte)0xB1, (byte)0x3D, (byte)0xAE },
        new byte[]{ (byte)0x42, (byte)0xB4, (byte)0x75, (byte)0x2E, (byte)0xA8, (byte)0xF3, (byte)0x14, (byte)0x88, (byte)0x0B, (byte)0xA4, (byte)0x54, (byte)0xD5, (byte)0x38, (byte)0x8F, (byte)0xBB, (byte)0x17 },
        new byte[]{ (byte)0xF6, (byte)0x16, (byte)0x0A, (byte)0x36, (byte)0x79, (byte)0xB7, (byte)0xB6, (byte)0xAE, (byte)0xD7, (byte)0x7F, (byte)0x42, (byte)0x5F, (byte)0x5B, (byte)0x8A, (byte)0xBB, (byte)0x34 },
        new byte[]{ (byte)0xDE, (byte)0xAF, (byte)0xBA, (byte)0xFF, (byte)0x18, (byte)0x59, (byte)0xCE, (byte)0x43, (byte)0x38, (byte)0x54, (byte)0xE5, (byte)0xCB, (byte)0x41, (byte)0x52, (byte)0xF6, (byte)0x26 },
        new byte[]{ (byte)0x78, (byte)0xC9, (byte)0x9E, (byte)0x83, (byte)0xF7, (byte)0x9C, (byte)0xCA, (byte)0xA2, (byte)0x6A, (byte)0x02, (byte)0xF3, (byte)0xB9, (byte)0x54, (byte)0x9A, (byte)0xE9, (byte)0x4C },
        new byte[]{ (byte)0x35, (byte)0x12, (byte)0x90, (byte)0x22, (byte)0x28, (byte)0x6E, (byte)0xC0, (byte)0x40, (byte)0xBE, (byte)0xF7, (byte)0xDF, (byte)0x1B, (byte)0x1A, (byte)0xA5, (byte)0x51, (byte)0xAE },
        new byte[]{ (byte)0xCF, (byte)0x59, (byte)0xA6, (byte)0x48, (byte)0x0F, (byte)0xBC, (byte)0x73, (byte)0xC1, (byte)0x2B, (byte)0xD2, (byte)0x7E, (byte)0xBA, (byte)0x3C, (byte)0x61, (byte)0xC1, (byte)0xA0 },
        new byte[]{ (byte)0xA1, (byte)0x9D, (byte)0xC5, (byte)0xE9, (byte)0xFD, (byte)0xBD, (byte)0xD6, (byte)0x4A, (byte)0x88, (byte)0x82, (byte)0x28, (byte)0x02, (byte)0x03, (byte)0xCC, (byte)0x6A, (byte)0x75 },
    };

    private static final byte[][] S = new byte[][]{
        { (byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76 },
        { (byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0, (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0 },
        { (byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC, (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15 },
        { (byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75 },
        { (byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0, (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84 },
        { (byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B, (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF },
        { (byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8 },
        { (byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5, (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2 },
        { (byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73 },
        { (byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB },
        { (byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C, (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79 },
        { (byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9, (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08 },
        { (byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6, (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A },
        { (byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E },
        { (byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94, (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF },
        { (byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16 },
    };

    static byte sBox(byte x)
    {
        return S[(((x & 0xFF) >>> 4))][x & 0xF];
    }

    static byte[] subBytes(byte[] s)
    {
        byte[] out = new byte[s.length];
        out[0] = sBox(s[0]);
        out[1] = sBox(s[1]);
        out[2] = sBox(s[2]);
        out[3] = sBox(s[3]);
        out[4] = sBox(s[4]);
        out[5] = sBox(s[5]);
        out[6] = sBox(s[6]);
        out[7] = sBox(s[7]);
        out[8] = sBox(s[8]);
        out[9] = sBox(s[9]);
        out[10] = sBox(s[10]);
        out[11] = sBox(s[11]);
        out[12] = sBox(s[12]);
        out[13] = sBox(s[13]);
        out[14] = sBox(s[14]);
        out[15] = sBox(s[15]);
        return out;
    }

    static byte[] shiftRows(byte[] s)
    {
        return new byte[]{
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]
        };
    }

    static byte[] aesEnc(byte[] s, byte[] rk)
    {
        s = subBytes(s);
        s = shiftRows(s);
        s = mixColumns(s);
        xorWith(rk, s);
        return s;
    }

    static byte mulX(byte p)
    {
        return (byte)(((p & 0x7F) << 1) ^ (((p & 0x80) >> 7) * 0x1B));
    }

    static byte[] xor(byte[] x, byte[] y, int yStart)
    {
        byte[] out = new byte[16];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(x[i] ^ y[yStart++]);
        }
        return out;
    }

    static void xorWith(byte[] x, byte[] z)
    {
        for (int i = 0; i < 16; ++i)
        {
            z[i] ^= x[i];
        }
    }

    private static byte[] mixColumns(byte[] s)
    {
        byte[] out = new byte[s.length];
        int j = 0;
        for (int i = 0; i < 4; i++)
        {
            out[j++] = (byte)(mulX(s[4 * i]) ^ mulX(s[4 * i + 1]) ^ s[4 * i + 1] ^ s[4 * i + 2] ^ s[4 * i + 3]);
            out[j++] = (byte)(s[4 * i] ^ mulX(s[4 * i + 1]) ^ mulX(s[4 * i + 2]) ^ s[4 * i + 2] ^ s[4 * i + 3]);
            out[j++] = (byte)(s[4 * i] ^ s[4 * i + 1] ^ mulX(s[4 * i + 2]) ^ mulX(s[4 * i + 3]) ^ s[4 * i + 3]);
            out[j++] = (byte)(mulX(s[4 * i]) ^ s[4 * i] ^ s[4 * i + 1] ^ s[4 * i + 2] ^ mulX(s[4 * i + 3]));
        }
        return out;
    }

    public int getDigestSize()
    {
        return DIGEST_SIZE;
    }
}