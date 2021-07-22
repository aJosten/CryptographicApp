import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Generate an elliptic key pair from a given passphrase and write the public key to a file.
 * Encrypt a data file under a given elliptic public key file.
 * Decrypt  a  given elliptic-encrypted  file  from  a  given password.
 * Sign  a  given  file  from  a  given  password  and  write  the signature to a file.
 * Verify a given data file and its signature file under a given public key file.
 * 
 * @author Andrew Josten
 */
public class EcurveFunctions {
	KMAC kmac;
	//The public generator, (4, some unique even number)
	private static final Ecurve G = new Ecurve(BigInteger.valueOf(4L), false);
	
	//The keys
	/**
	 * The private key, a scalar s
	 */
	private BigInteger s;
	
	/**
	 * The public key, curve point V
	 */
	private Ecurve V;
	
	public EcurveFunctions(){
		kmac = new KMAC();		
	}
	
	/**
	 * Generate a Schnorr/ECDHIES key pair from passphrase pw
	 * s<-KMACXOF256(pw,"", 512, "K"); s<-4s
	 * V<-s*G
	 * key pair: (s, V)
	 * 
	 * @params pw the password
	 */
	public void KeyPair(byte[] pw){
		s = null;
		V = null;
		
		byte[] scalarHash = kmac.KMACXOF256(pw, new byte[] {}, 512, "K");
		//Using the concat here to avoid negative bigint.		
		BigInteger bigS = new BigInteger(concat(new byte[] {0},scalarHash));
		bigS = bigS.multiply(BigInteger.valueOf(4L)); //s <- 4s
		Ecurve pointV = G.exponentiation(bigS);//V<-s*G	
		//The key pair is (s,V)
		s = bigS;
		V = pointV;		
	}

	public BigInteger getS() {return s;}
	public Ecurve getV() {return V;}
	public Ecurve getG(){return G;}
	
	/**
	 * Encrypting a byte array m under the (Schnorr/ECDHIES) public key V:
	 * @param m
	 * @return A special tuple-like object called CurveGram (Z,c,t)
	 */
	public CurveGram encrypt(byte[] m){
		//k <- Random(512)
		SecureRandom sr = new SecureRandom();
        byte[] rand = new byte[65];//spare byte to ensure postive bigint. This is necessary for the process to work
        sr.nextBytes(rand);
        rand[0] = 0; //no negatives
        byte [] k = rand;

        //k<-4k
        BigInteger bigK = new BigInteger(k);
        bigK = bigK.multiply(BigInteger.valueOf(4L));
        
        //W<-k*V
        Ecurve W = this.V.exponentiation(bigK);
        //Z <- k*G
        Ecurve Z = G.exponentiation(bigK);
        
        //ke||ka KMACXOF256(Wx "", 1024, "S")
        byte[] keka = kmac.KMACXOF256(W.getX().toByteArray(), new byte[] {}, 1024, "P");
        byte[] ke = Arrays.copyOfRange(keka, 0, 64);
        byte[] ka = Arrays.copyOfRange(keka, 64, 128);
        
        //c <- KMACXOF256(ke, "", |m|, "PKE") xor m
        byte[] c = kmac.KMACXOF256(ke, new byte[] {}, m.length * 8, "PKE");
        byte[] xorC = new byte[c.length];
        for (int i = 0; i < m.length; i++) {
        	xorC[i] = (byte) (c[i] ^ m[i]);
        }
        
        //t<-KMACXOF256(ka, m, 512, "PKA")
        byte t[] = kmac.KMACXOF256(ka, m, 512, "PKA");
        
        //cryptogram
        return new CurveGram(Z, xorC, t);
	}
	
	/**
	 * Decrypts a given ecurve encryption under password pw
	 * @param r the Curvegram (Z,c,t)
	 * @param pw the passphrase in byte[]
	 * @return message in bytes if decrpytion is successful
	 */
	public byte[] decrypt(CurveGram r, byte[] pw) {		
		//s <- KMACXOF256(pw, "", 512, "K")
		byte[] tempS = kmac.KMACXOF256(pw, new byte[] {}, 512, "K");
		tempS = concat(new byte[] {0}, tempS);//ensure postive bigint
		//s<-4s
		BigInteger bigS = new BigInteger(tempS);
        bigS = bigS.multiply(BigInteger.valueOf(4L));
		//this is essentailly the private key, s
		
		//W <- s*Z
		Ecurve W = r.Z.exponentiation(s);
		
		//ke||ka KMACXOF256(Wx, "", 1024, "S")
        byte[] keka = kmac.KMACXOF256(W.getX().toByteArray(), new byte[] {}, 1024, "P");
        byte[] ke = Arrays.copyOfRange(keka, 0, 64);
        byte[] ka = Arrays.copyOfRange(keka, 64, 128);
        
        //m <- KMACXOF256(ke, "", |c|, "PKE") xor c
        byte[] c = r.c;
        byte[] m = kmac.KMACXOF256(ke, new byte[] {}, c.length * 8, "PKE");
        byte[] xorM = new byte[m.length];
        for (int i = 0; i < c.length; i++) {
        	xorM[i] = (byte) (m[i] ^ c[i]);
        }

        //t'<-KMACXOF256(ka, m, 512, "PKA")
        byte tPrime[] = kmac.KMACXOF256(ka, xorM, 512, "PKA");
                
        if(Arrays.equals(tPrime, r.t)){
        	return xorM;
        }
        else {
        	System.out.println("Failed to decrypt: Ecurve");
        	return new byte[] {};
        }
	}
		
	/**
	 * Generates a signature
	 * @param pw
	 * @param m
	 * @return
	 */
	public byte[] sigGenerator(byte[] pw, byte[] m) {
		//this part essentially the keyPair/*		
		//s <- KMACXOF256(pw, "", 512, "K")
		byte[] tempS = kmac.KMACXOF256(pw, new byte[] {}, 512, "K");
		tempS = concat(new byte[] {0}, tempS);//ensure postive bigint
		
		//s<-4s
		BigInteger bigS = new BigInteger(tempS);
        bigS = bigS.multiply(BigInteger.valueOf(4L));

        //k <- KMACXOF256(pw, m, 512, "N")
  		byte[] k = kmac.KMACXOF256(bigS.toByteArray(), m, 512, "N");
  		k = concat(new byte[] {0}, k);//ensure postive bigint
  		  		
  		//k<-4k
  		BigInteger bigK = new BigInteger(k);
  		bigK = bigK.multiply(BigInteger.valueOf(4L));
  		Ecurve U = G.exponentiation(bigK);//U <- k*G
  		
  		//h<-KMACXOF256(Ux, m, 512, "T"); 
  		byte[] h = kmac.KMACXOF256(U.getX().toByteArray(), m, 512, "T");
  		h = concat(new byte[] {0}, h);//ensure postive bigint
  		BigInteger bigH = new BigInteger(h);  		
  		
  		//r = number of points on e-curve
  		//r = 2^519 - 33755...
  		BigInteger b = new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
  		BigInteger r = BigInteger.valueOf(2L).pow(519).subtract(b);
  		
  		//z<-(k–hs) mod r
  		byte[] z = ((bigK.subtract(bigH.multiply(bigS))).mod(r)).toByteArray();
  		BigInteger bigZ = new BigInteger(z);
  		
  		//corrections for signs
  		byte[] ret = new byte[130];
  		if(bigH.signum() < 0) {
  			Arrays.fill(ret, 0, 130/2 - h.length, (byte) 0xff); 
  		}
  		if(bigZ.signum() < 0) {
  			Arrays.fill(ret, 130 / 2, 130-z.length, (byte) 0xff);
  		}
  		System.arraycopy(h, 0, ret, 130/2 - h.length, h.length);
        System.arraycopy(z, 0, ret, 130-z.length, z.length);
  		
  		return ret;
	}	
	
	/**
	 * Returns true if a bit signature is proeprly verified
	 * @param sig
	 * @param m
	 * @return
	 */
	public boolean verify(byte[][] sig, byte[] m) {			
		BigInteger z = new BigInteger(sig[1]);
		BigInteger h = new BigInteger(sig[0]);
		
		Ecurve temp1 = G.exponentiation(z);
		Ecurve temp2 = V.exponentiation(h);
		Ecurve U = temp1.sum(temp2);
		
		byte[] hPrime = kmac.KMACXOF256(U.getX().toByteArray(), m, 512, "T");
		hPrime = concat(new byte[] {0}, hPrime);//ensure postive bigint
		
		if(Arrays.equals(hPrime, sig[0])) {
			return true;
		}
		else {
			return false;
		}
	}
	
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
}