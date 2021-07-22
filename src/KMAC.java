import java.util.Arrays;

/**
 * This class contains the primary implementation of the KMAC algorithms and supporting functions
 * @author Andrew Josten
 *
 */
public class KMAC {
	SHA3 s;
	
	public KMAC() {
		s = new SHA3();
	}
	
	/**
	 * This method calls the KMACXOF256 algorithm:
	 * 
	 *  newX = bytepad(encode_string(K), 136) || X || right_encode(0)
	 *  return cSHAKE256(newX, L, “KMAC”, S)
	 *
	 * @param K Key. Bit string (as in, byte array) of any length (including 0)
	 * @param X Main input. Byte string(array) of any length (including 0)
	 * @param L Output length in bits
	 * @param S Optional customization bit string. (If not desired, set as empty string, "")
	 * @return
	 */
	public byte[] KMACXOF256(byte[] K, byte[] X, int L, String S) {		
		byte[] newX = concat(bytepad(encode_string(K), 136), X);
		newX = concat(newX , right_encode(0));
		return cSHAKE256(newX, L, "KMAC", S);		
	}
		
	/** 
	 * The method calls the cShake256 algoirthm
	 * If N = "" and S = "":
	 *		return SHAKE256(X, L);
	 *	Else:
	 *		return KECCAK[512]( bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)		
	 *		
	 * Note: cSHAKE256(X, L, "", "") = SHAKE256(X, L)
	 * 
	 * @param X Main input string
	 * @param L Requested output length
	 * @param N Function name bit string (eg KMAC). Empty N means default cSHAKE
	 * @param S Customizable bit string.
	 * @return
	 */
	public byte[] cSHAKE256(byte[] X, int L, String N, String S) {
		if(N.equals("") && S.equals("")) {			
			byte[] kArg = Arrays.copyOf(X, X.length + 1);
	        int padding = 136 - kArg.length % 136;
	        
	        if(padding == 1) {
	        	kArg[X.length] = (byte) 159;
	        }
	        else {
	        	kArg[X.length] = (byte) 31;
	        }
	        return s.Keccak(1088, 512, X, L);
		}
		else {
			byte[] kArg = concat(encode_string(N.getBytes()), encode_string(S.getBytes()));
			kArg = concat(bytepad(kArg, 136), X);
			kArg = concat(kArg, new byte[] {0x04});			
			return s.Keccak(1088, 512, kArg, L);
			
			//This was my original attempt to call the  keccak algorithm. It was not working out so I referred to Keccak home page
			//And implemented a sponge inspired from their code instead
			/*
			s.sha3_init(L);
			s.sha3_update(kArg, L);
			return s.sha3_final();*/
		}
	}

	/* Supporting Functions:
	 * These functions include pad left, pad right, bytepad, encode string, and my own concatenation function (|| in documentation)
	 */
	
	/**
	 * Takes two byte arrays and concatenates them together.
	 * Equivalent to the ' || ' in the documentation.
	 * @param a The first byte array/ bit string. Will be in front of b
	 * @param b the second array
	 * @return
	 */
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

	/**
	 * prepends an encoding of the integer w to an input string X, then pads
	 * the result with zeros until it is a byte string whose length in bytes is a multiple of w
	 * @param X byte[] to be padded
	 * @param w an int to be encoded onto the end
	 * @return byte[]
	 */
	private byte[] bytepad(byte[] X, int w) {
		byte[] encoded = left_encode(w);
		
		int zSize = X.length + encoded.length;
		zSize += w - (X.length + encoded.length) % w;
		
		byte[] z = Arrays.copyOf(encoded, zSize);
        System.arraycopy(X, 0, z, encoded.length, X.length);
        return z;
	}

	/**
	 * Encodes bit strings in a way that may be parsed unambiguously from the beginning of the string
	 * @param S bit string to encode
	 */
	private byte[] encode_string(byte[] S) {
		return concat(left_encode(S.length*8), S);
	}
	
	/**
	 * Encodes so it might be parsed from end of string
	 * 
	 * Used this as some reference help
	 * https://crypto.stackexchange.com/questions/75269/sha3-the-left-right-encode-functions
	 */
	private byte[] right_encode(long x) {
		if(x == 0) {
			return new byte[] {0, 1};
		}
		int index = 0;
        byte[] temp = new byte[8];

        
        while (x > 0) {
            byte b = (byte) (x & 255L);
            x = x>>>(8);
            temp[7 - index++] = b; 
        }
        
        byte[] encoded = new byte[index + 1];
        System.arraycopy(temp, 8 - index, encoded, 0, index);
        
        encoded[encoded.length - 1] = (byte) index;
        return encoded;
	}
	
	/**
	 * Encodes so it might be parsed from beginning of string
	 */
	private byte[] left_encode(long x){
		if(x == 0) {
			return new byte[] {1, 0};
		}
		int index = 0;
		byte[] temp = new byte[8];

        
        while (x > 0) {
            byte b = (byte) (x & 255L);
            x = x>>>(8);
            temp[7 - index++] = b;
        }
        
        byte[] encoded = new byte[index + 1];
        
        System.arraycopy(temp, 8 - index, encoded, 1, index);
        encoded[0] = (byte) index;
        return encoded;
	}
}
