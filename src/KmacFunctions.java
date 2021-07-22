import java.security.SecureRandom;
import java.util.Arrays;

/**
 * This class contains the mechanisms of high level specification
 * for the kmac/keccak related parts
 * @author Andrew Josten
 *
 */
public class KmacFunctions {
	KMAC kmac;
	
	public KmacFunctions() {
		kmac = new KMAC();
	}
	
	/**
	 * Computes cryptographic hash of byte array m
	 * h<-KMACXOF256("", m, 512, "D")
	 * @param byte array m (message)
	 * @return a hash h built via byte array m
	 */
	public byte[] cryptographicHash(byte[] m){
		return kmac.KMACXOF256(new byte[] {}, m, 512, "D");
	}
	
	/**
	 * Computes authentication tag t of byte array m given password pw
	 * h<-KMACXOF256("", m, 512, "D")
	 * @param byte array m (message)
	 * @param byte array pw (passphrase)
	 * @return a hash h built via byte array m
	 */
	public byte[] authenticationTag(byte[] m, byte[] pw){
		return kmac.KMACXOF256(pw, m, 512, "T");
	}
	
	/**
	 * Encrypting a byte array m symmetrically under passphrase pw:
	 * @param m the byte array (message)
	 * @param pw the byte array passphrase
	 * @return Symmetric cryptogram: byte array of elements (z,c,t)
	 */
	public byte[] encrypt(byte[] m, byte[] pw){
		//z <- Random(512), 64*8 =512
		SecureRandom sr = new SecureRandom();
        byte[] rand = new byte[64];
        sr.nextBytes(rand);
        byte [] z = rand;
        
        //ke||ka KMACXOF256(z|| pw, "", 1024, "S")
        byte[] zpw = concat(z,pw);
        byte[] keka = kmac.KMACXOF256(zpw, new byte[] {}, 1024, "S");        
        byte[] ke = Arrays.copyOfRange(keka, 0, 64);
        byte[] ka = Arrays.copyOfRange(keka, 64, 128);
        
        //c <- KMACXOF256(ke, "", |m|, "SKE") xor m
        byte[] c = kmac.KMACXOF256(ke, new byte[] {}, m.length * 8, "SKE");
        
        byte[] xorC = new byte[c.length];
        for (int i = 0; i < m.length; i++) {
        	xorC[i] = (byte) (c[i] ^ m[i]);
        }
        
        //t<-KMACXOF256(ka, m, 512, "SKA")
        byte t[] = kmac.KMACXOF256(ka, m, 512, "SKA");
        
        byte[][] r = new byte[3][];
        r[0] = z;
        r[1] = xorC;
        r[2] = t;
        
        return concat(r[0], concat(r[1], r[2]));
	}
	
	/**
	 * Decrypting a symmetric cryptogram under pw
	 * @param sym a 2d byte array: (z,c,t)
	 * @param pw the byte array passphrase
	 * @return Decrpyted message. Only if successfully decrpyted
	 */
	public byte[] decrypt(byte[] gram, byte[] pw){
		
		byte[][] zct = new byte[3][];
		zct[0] = Arrays.copyOfRange(gram, 0, 64);
		zct[1] = Arrays.copyOfRange(gram, 64, gram.length - 64);
		zct[2] = Arrays.copyOfRange(gram, gram.length - 64, gram.length);
		
        //ke||ka KMACXOF256(z|| pw, "", 1024, "S")
        byte[] keka = kmac.KMACXOF256(concat(zct[0],pw), new byte[] {}, 1024, "S");
        byte[] ke = Arrays.copyOfRange(keka, 0, 64);
        byte[] ka = Arrays.copyOfRange(keka, 64, 128);       
        
        //m <- KMACXOF256(ke, "", |c|, "SKE") xor c
        byte[] c = zct[1];
        byte[] m = kmac.KMACXOF256(ke, new byte[] {}, c.length * 8, "SKE");
        byte[] xorM = new byte[m.length];
        for (int i = 0; i < c.length; i++) {
        	xorM[i] = (byte) (m[i] ^ c[i]);
        }
        
        //t'<-KMACXOF256(ka, m, 512, "SKA")
        byte tPrime[] = kmac.KMACXOF256(ka, xorM, 512, "SKA");
        
        if(Arrays.equals(zct[2], tPrime)){
        	return xorM;
        }
        else {
        	System.out.println("Failed to decrypt");
        	return new byte[] {};
        }
	}
	
	
	
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
}
