package mscof.jcryptool.blake2;

import java.math.BigInteger;

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

public class BLAKE2bAlgorithm {
	
	// Java has an issue with the reference implementation as Java does not support
	// unsigned variables.  Alternatives will be used where possible. - Jonathan
	
	//TODO: Fix access levels
	
	private Boolean isInitialized = false;
	
	private int bufferFilled;
	private byte[] buffer = new byte[128];
	
	private BigInteger[] m = new BigInteger[16];
	private BigInteger[] h = new BigInteger[8];
	private long counter0;
	private long counter1;
	private BigInteger finalizationFlag0;
	private BigInteger finalizationFlag1;
	
	private final int NumberOfRounds = 12;
	private final int BlockSizeInBytes = 128;
	
	//WORKAROUND: Pass the hex as a string into BigInteger
	final BigInteger IV0 = new BigInteger("6A09E667F3BCC908UL", 16);
	final BigInteger IV1 = new BigInteger("BB67AE8584CAA73BUL", 16);
	final BigInteger IV2 = new BigInteger("3C6EF372FE94F82BUL", 16);
	final BigInteger IV3 = new BigInteger("A54FF53A5F1D36F1UL", 16);
	final BigInteger IV4 = new BigInteger("510E527FADE682D1UL", 16);
	final BigInteger IV5 = new BigInteger("9B05688C2B3E6C1FUL", 16);
	final BigInteger IV6 = new BigInteger("1F83D9ABFB41BD6BUL", 16);
	final BigInteger IV7 = new BigInteger("5BE0CD19137E2179UL", 16);
	
	private int[] Sigma = new int[NumberOfRounds * 16];		// TODO: Add values
	
	
	
}
