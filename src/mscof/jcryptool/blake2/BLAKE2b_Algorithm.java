package mscof.jcryptool.blake2;

import java.util.ArrayList;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class BLAKE2b_Algorithm {
	
	// Byte array/buffers
	private long[] _h = new long[8];		// hash chain value
	private long[] _m = new long[16];		// message block
	private byte[] _buf = new byte[128];	// buffer
	
	// BLAKE2b initial value constants
	final long IV0 = 0x6A09E667F3BCC908L;
	final long IV1 = 0xBB67AE8584CAA73BL;
	final long IV2 = 0x3C6EF372FE94F82BL;
	final long IV3 = 0xA54FF53A5F1D36F1L;
	final long IV4 = 0x510E527FADE682D1L;
	final long IV5 = 0x9B05688C2B3E6C1FL;
	final long IV6 = 0x1F83D9ABFB41BD6BL;
	final long IV7 = 0x5BE0CD19137E2179L;
	
	// Control variables
	private int _bufferFilled;
	private int _counter0;
	private int _counter1;
	private long _finalizationFlag0;
	private long _finalizationFlag1;
	private Boolean _isInitialized = false;
	
	// Assorted constants
	private final int NumberOfRounds = 12;
	private final int BlockSizeInBytes = 128;
	
	// BLAKE2B permutations table
	private int[] Sigma = {
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

	public void Init() {
		
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
		
		_isInitialized = true;
	}
	
	@SuppressWarnings("unused")
	
	//Seemingly unused parameters.
	//private long[] Compress(byte[] block, int start)
	public void Compress(byte[] block)
	{
		
		long[] h = _h;
		long[] m = _m;

		long v0 = h[0];
		long v1 = h[1];
		long v2 = h[2];
		long v3 = h[3];
		long v4 = h[4];
		long v5 = h[5];
		long v6 = h[6];
		long v7 = h[7];

		long v8 = IV0;
		long v9 = IV1;
		long v10 = IV2;
		long v11 = IV3;
		long v12 = IV4 ^ _counter0;
		long v13 = IV5 ^ _counter1;
		long v14 = IV6 ^ _finalizationFlag0;
		long v15 = IV7 ^ _finalizationFlag1;

		for (int r = 0; r < NumberOfRounds; ++r)
		{
			// G0 (r,0,v0,v4,v8,v12) 
			v0 = v0 + v4 + m[Sigma[16 * r + 2 * 0 + 0]];
			v12 ^= v0;
			v12 = ((v12 >> 32) | (v12 << (64 - 32)));
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = ((v4 >> 24) | (v4 << (64 - 24)));
			v0 = v0 + v4 + m[Sigma[16 * r + 2 * 0 + 1]];
			v12 ^= v0;
			v12 = ((v12 >> 16) | (v12 << (64 - 16)));
			v8 = v8 + v12;
			v4 ^= v8;
			v4 = ((v4 >> 63) | (v4 << (64 - 63)));

			// G1 (r,1,v1,v5,v9,v13) 
			v1 = v1 + v5 + m[Sigma[16 * r + 2 * 1 + 0]];
			v13 ^= v1;
			v13 = ((v13 >> 32) | (v13 << (64 - 32)));
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = ((v5 >> 24) | (v5 << (64 - 24)));
			v1 = v1 + v5 + m[Sigma[16 * r + 2 * 1 + 1]];
			v13 ^= v1;
			v13 = ((v13 >> 16) | (v13 << (64 - 16)));
			v9 = v9 + v13;
			v5 ^= v9;
			v5 = ((v5 >> 63) | (v5 << (64 - 63)));

			// G2 (r,2,v2,v6,v10,v14) 
			v2 = v2 + v6 + m[Sigma[16 * r + 2 * 2 + 0]];
			v14 ^= v2;
			v14 = ((v14 >> 32) | (v14 << (64 - 32)));
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = ((v6 >> 24) | (v6 << (64 - 24)));
			v2 = v2 + v6 + m[Sigma[16 * r + 2 * 2 + 1]];
			v14 ^= v2;
			v14 = ((v14 >> 16) | (v14 << (64 - 16)));
			v10 = v10 + v14;
			v6 ^= v10;
			v6 = ((v6 >> 63) | (v6 << (64 - 63)));

			// G3 (r,3,v3,v7,v11,v15) 
			v3 = v3 + v7 + m[Sigma[16 * r + 2 * 3 + 0]];
			v15 ^= v3;
			v15 = ((v15 >> 32) | (v15 << (64 - 32)));
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = ((v7 >> 24) | (v7 << (64 - 24)));
			v3 = v3 + v7 + m[Sigma[16 * r + 2 * 3 + 1]];
			v15 ^= v3;
			v15 = ((v15 >> 16) | (v15 << (64 - 16)));
			v11 = v11 + v15;
			v7 ^= v11;
			v7 = ((v7 >> 63) | (v7 << (64 - 63)));

			// G4 (r,4,v0,v5,v10,v15) 
			v0 = v0 + v5 + m[Sigma[16 * r + 2 * 4 + 0]];
			v15 ^= v0;
			v15 = ((v15 >> 32) | (v15 << (64 - 32)));
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = ((v5 >> 24) | (v5 << (64 - 24)));
			v0 = v0 + v5 + m[Sigma[16 * r + 2 * 4 + 1]];
			v15 ^= v0;
			v15 = ((v15 >> 16) | (v15 << (64 - 16)));
			v10 = v10 + v15;
			v5 ^= v10;
			v5 = ((v5 >> 63) | (v5 << (64 - 63)));

			// G5 (r,5,v1,v6,v11,v12) 
			v1 = v1 + v6 + m[Sigma[16 * r + 2 * 5 + 0]];
			v12 ^= v1;
			v12 = ((v12 >> 32) | (v12 << (64 - 32)));
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = ((v6 >> 24) | (v6 << (64 - 24)));
			v1 = v1 + v6 + m[Sigma[16 * r + 2 * 5 + 1]];
			v12 ^= v1;
			v12 = ((v12 >> 16) | (v12 << (64 - 16)));
			v11 = v11 + v12;
			v6 ^= v11;
			v6 = ((v6 >> 63) | (v6 << (64 - 63)));

			// G6 (r,6,v2,v7,v8,v13) 
			v2 = v2 + v7 + m[Sigma[16 * r + 2 * 6 + 0]];
			v13 ^= v2;
			v13 = ((v13 >> 32) | (v13 << (64 - 32)));
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = ((v7 >> 24) | (v7 << (64 - 24)));
			v2 = v2 + v7 + m[Sigma[16 * r + 2 * 6 + 1]];
			v13 ^= v2;
			v13 = ((v13 >> 16) | (v13 << (64 - 16)));
			v8 = v8 + v13;
			v7 ^= v8;
			v7 = ((v7 >> 63) | (v7 << (64 - 63)));

			// G7 (r,7,v3,v4,v9,v14) 
			v3 = v3 + v4 + m[Sigma[16 * r + 2 * 7 + 0]];
			v14 ^= v3;
			v14 = ((v14 >> 32) | (v14 << (64 - 32)));
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = ((v4 >> 24) | (v4 << (64 - 24)));
			v3 = v3 + v4 + m[Sigma[16 * r + 2 * 7 + 1]];
			v14 ^= v3;
			v14 = ((v14 >> 16) | (v14 << (64 - 16)));
			v9 = v9 + v14;
			v4 ^= v9;
			v4 = ((v4 >> 63) | (v4 << (64 - 63)));
		}

		
		h[0] ^= v0 ^ v8;
		h[1] ^= v1 ^ v9;
		h[2] ^= v2 ^ v10;
		h[3] ^= v3 ^ v11;
		h[4] ^= v4 ^ v12;
		h[5] ^= v5 ^ v13;
		h[6] ^= v6 ^ v14;
		h[7] ^= v7 ^ v15;
	}
	
	public byte[] getHash() {
		
		byte[] output = new byte[64];
		
		for (int i = 0; i < _h.length; i++) {
			byte[] buffer = new byte[8];
			
			buffer = longToByteArray(_h[i]);
			
			System.arraycopy(buffer, 0, output, i*8, 8);
		}
		
		return output;
	}
	
	// Conversion from long to byte array
	public long byteArrayToLong(byte[] b, int offset) {
		ByteBuffer buf = ByteBuffer.wrap(b);
		return buf.getLong(offset);
	}
	
	// Conversion from byte array to long
	public byte[] longToByteArray(long l) {
		byte b[] = new byte[8];
		ByteBuffer buf = ByteBuffer.wrap(b);
		buf.putLong(l);
		return b;
	}
	
	// Converts bytes to a human-readable String of hex characters
	public String bytesToHex(byte[] bytes) {
	    final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

    public void Reset() {
    	
    }
}

	

