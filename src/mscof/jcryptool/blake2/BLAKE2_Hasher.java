package mscof.jcryptool.blake2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BLAKE2_Hasher {

	private byte[] messageBlock;
	private ArrayList<byte[]> splitBlock = new ArrayList<byte[]>();
	private byte[][] splitBlock_array;
	private byte[] currentBlock = new byte[128];
	
	private int messageBlockLength;
	private int splitArrayLength;
	
	public BLAKE2_Hasher(String input) throws Exception {
		this.messageBlock = input.getBytes();
		messageBlockLength = messageBlock.length;
		
		if (messageBlock.length == 128) {
			splitArrayLength = 1;
		}
		
		if (messageBlock.length < 128) {
			PadBytes(messageBlock);
			splitArrayLength = 1;
		}
		
		if (messageBlock.length > 128) {
			splitArrayLength = CalculateSplitArrayLength(messageBlock);
			byte[] tempArray2 = new byte[128];
			
			// if the message block is a multiple of 128, copy directly
			if (messageBlock.length % 128 == 0) {
				
				for (int i = 0; i < splitArrayLength; i++) {
					byte[] tempArray = new byte[128];
					int offset = i * 128;
					System.arraycopy(messageBlock, offset, tempArray, 0, 128);
					
					splitBlock.add(tempArray);
				}
			} else {
				for (int i = 0; i < (splitArrayLength - 1); i++) {
					byte[] tempArray = new byte[128];
					int offset = i * 128;
					System.arraycopy(messageBlock, offset, tempArray, 0, 128);
					
					splitBlock.add(tempArray);
				}
				// Last bit in the array
				System.arraycopy(messageBlock, splitArrayLength, tempArray2, (splitArrayLength * 128) - 1, messageBlock.length - (splitArrayLength*128));
				tempArray2 = PadBytes(tempArray2);
			}
			splitBlock_array = new byte[splitBlock.size()][];
			splitBlock_array = splitBlock.toArray(splitBlock_array);
		}
	}
	
	public BLAKE2_Hasher(byte[] input) {
		this.messageBlock = input;
	}
	
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
	
	public byte[] CalculateHash() {
		
		BLAKE2b_Algorithm hasher = new BLAKE2b_Algorithm();
		hasher.Init();
		
		for (int i = 0; i < splitArrayLength; i++) {
			hasher.Compress(splitBlock_array[i]);
		}
		
		return hasher.getHash();
		
	}
	
	private byte[] PadBytes(byte[] input) throws Exception {
		byte[] output = new byte[128];
		
		// fill array with zeros
		for (int i = 0; i < output.length; i++) {
			output[i] = 0x00;
		}
		
		// copy input elements into output array
		for (int i = 0; i < input.length; i++) {
			output[i] = input[i];
		}
		
		// Exception handling
		if (output.length != 128) {
			throw new Exception("Output array is of incorrect length");
		}
		
		return output;
	}
	
	private int CalculateSplitArrayLength(byte[] input) {
		int arrayLength = input.length;
		int splitArrayLength = (arrayLength / 128) + 1;
		
		return splitArrayLength;
		
	}
}
