package mscof.jcryptool.blake2;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;

/*
 * Authored by Jonathan Claudio and Craig Strange, 2013.
 * Based on the reference BLAKE2b C# Implementation written by Chris Winnerlein
 * 
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * BLAKE2 was designed by 
 */

public class BLAKE2bAlgorithm extends java.security.MessageDigest{

	protected BLAKE2bAlgorithm(String algorithm) {
		super("BLAKE2b");
	}
	private Boolean _isInitialized = false;

	private int _bufferFilled;
	private byte[] _buf = new byte[128];

	private BigInteger[] _m = new BigInteger[16];
	private BigInteger[] _h = new BigInteger[8];
	private int _counter0;
	private int _counter1;
	private BigInteger _finalizationFlag0;
	private BigInteger _finalizationFlag1;

	private final BigInteger ulongMaxValue = new BigInteger("FFFFFFFFFFFFFFFF",16);
	
	
	private final int NumberOfRounds = 12;
	private final int BlockSizeInBytes = 128;

	final BigInteger IV0 = new BigInteger("6A09E667F3BCC908",16);
	final BigInteger IV1 = new BigInteger("BB67AE8584CAA73B",16);
	final BigInteger IV2 = new BigInteger("3C6EF372FE94F82B",16);
	final BigInteger IV3 = new BigInteger("A54FF53A5F1D36F1",16);
	final BigInteger IV4 = new BigInteger("510E527FADE682D1",16);
	final BigInteger IV5 = new BigInteger("9B05688C2B3E6C1F",16);
	final BigInteger IV6 = new BigInteger("1F83D9ABFB41BD6B",16);
	final BigInteger IV7 = new BigInteger("5BE0CD19137E2179",16);

	private static int[] Sigma = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
		11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
		7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
		9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
		2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
		12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
		13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
		6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
		10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
	};
	
    static long getLong(byte[] b, int off) {
        return  ((b[off + 7] & 0xFFL)      ) +
                ((b[off + 6] & 0xFFL) <<  8) +
                ((b[off + 5] & 0xFFL) << 16) +
                ((b[off + 4] & 0xFFL) << 24) +
                ((b[off + 3] & 0xFFL) << 32) +
                ((b[off + 2] & 0xFFL) << 40) +
                ((b[off + 1] & 0xFFL) << 48) +
                (((long) b[off])      << 56);
    }
    //long to byte conversion
    static void putLong(byte[] b, int off, long val) {
        b[off + 7] = (byte) (val       );
        b[off + 6] = (byte) (val >>>  8);
        b[off + 5] = (byte) (val >>> 16);
        b[off + 4] = (byte) (val >>> 24);
        b[off + 3] = (byte) (val >>> 32);
        b[off + 2] = (byte) (val >>> 40);
        b[off + 1] = (byte) (val >>> 48);
        b[off    ] = (byte) (val >>> 56);
    }
	
	partial void Compress(byte[] block, int start);

	public void Initialize(BigInteger[] config)
	{
		if (config == null)
			throw new Exception("config");
		if (config.length != 8)
			throw new Exception("config length must be 8 words");
		_isInitialized = true;

		_h[0] = IV0;
		_h[1] = IV1;
		_h[2] = IV2;
		_h[3] = IV3;
		_h[4] = IV4;
		_h[5] = IV5;
		_h[6] = IV6;
		_h[7] = IV7;

		_counter0 = 0;
		_counter1 = 0;
		_finalizationFlag0 = 0;
		_finalizationFlag1 = 0;

		_bufferFilled = 0;

		
		Arrays.fill(_buf, (Byte) null);

		for (int i = 0; i < 8; i++)
			_h[i] ^= config[i];
	}

	public void HashCore(byte[] array, int start, int count)
	{
		if (!_isInitialized)
			throw new Exception("Not initialized");
		if (array == null)
			throw new Exception("array");
		if (start < 0)
			throw new Exception("start");
		if (count < 0)
			throw new Exception("count");
		if ((long)start + (long)count > array.length)
			throw new Exception("start+count");
		int offset = start;
		int bufferRemaining = BlockSizeInBytes - _bufferFilled;

		if ((_bufferFilled > 0) && (count > bufferRemaining))
		{
			
			System.arraycopy(array, offset, _buf, _bufferFilled, bufferRemaining);
			_counter0 += BlockSizeInBytes;
			if (_counter0 == 0)
				_counter1++;
			Compress(_buf, 0);
			offset += bufferRemaining;
			count -= bufferRemaining;
			_bufferFilled = 0;
		}

		while (count > BlockSizeInBytes)
		{
			_counter0 += BlockSizeInBytes;
			if (_counter0 == 0)
				_counter1++;
			Compress(array, offset);
			offset += BlockSizeInBytes;
			count -= BlockSizeInBytes;
		}

		if (count > 0)
		{
			System.arraycopy(array, offset, _buf, _bufferFilled, count);
			_bufferFilled += count;
		}
	}

	public byte[] HashFinal()
	{
		return HashFinal(false);
	}

	public byte[] HashFinal(Boolean isEndOfLayer)
	{
		if (!_isInitialized)
			throw new Exception("Not initialized");
		_isInitialized = false;

		//Last compression
		_counter0 += _bufferFilled;
		_finalizationFlag0 = ulongMaxValue;
		if (isEndOfLayer)
			_finalizationFlag1 = ulongMaxValue;
		for (int i = _bufferFilled; i < _buf.length; i++)
			_buf[i] = 0;
		Compress(_buf, 0);

		//Output
		byte[] hash = new byte[64];
		for (int i = 0; i < 8; ++i)
			UInt64ToBytes(_h[i], hash, i << 3);
		return hash;
	}
	@Override
	protected void engineUpdate(byte input) {
		// TODO Auto-generated method stub
		
	}
	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		// TODO Auto-generated method stub
		
	}
	@Override
	protected byte[] engineDigest() {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	protected void engineReset() {
		// TODO Auto-generated method stub
		
	}
	
	
	
}
