import java.math.BigInteger;
import java.util.Arrays;

/**
 * Contains all methods and constructors of Elliptic curve arithmetic
 * 
 * @author Andrew Josten
 */
public class Ecurve {
	//The coords of our point
	private BigInteger X;
	private BigInteger Y;
	
	//Mersenne prime
	private final static BigInteger MersenneP = BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE);
	//d = -376014
	private final BigInteger d = BigInteger.valueOf(-376014);
	
	/*Various constructors*/
	/**
	 * Neutral element constructor
	 * In Edwards curves, the neutral element is (0,1)
	 */
	public Ecurve() {
		X = BigInteger.ZERO;
		Y = BigInteger.ONE;
	}
	
	/**
	 * Curve point constructor (x,y)
	 */
	public Ecurve(BigInteger a, BigInteger b) {
		X = a;
		Y = b;
	}
	
	/**
	 * X coord and least sigbit of y
	 */
	public Ecurve(BigInteger a, boolean lsb) {
		X = a;
		
		BigInteger numerator = BigInteger.ONE.subtract(a.pow(2));
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(a.pow(2)));
        
        BigInteger sqrt = sqrt(numerator.multiply(denominator.modInverse(MersenneP)), MersenneP, lsb);
        if (sqrt == null) {//if return null, we fail
        	throw new IllegalArgumentException();
        }

        Y = sqrt.mod(MersenneP);
	}
	
	/**
	 * TAKEN FROM ASSIGNMENT DESCRIPTION
	 * 
	 * Compute a square root of v mod p with a specified
	 * least significant bit, if such a root exists.
	 * @param   v   the radicand.
	 * @param   p   the modulus (must satisfy p mod 4 = 3)
	 * @param   lsb desired least significant bit (true: 1, false: 0).
	 * @return  a square root r of v mod p with r mod 2 = 1 iff lsb = true
	 * if such a root exists, otherwise null.
	 */
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
		assert(p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
		if(v.signum() == 0) {
			return BigInteger.ZERO;
		}
		BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		if(r.testBit(0) != lsb) {
			r = p.subtract(r); // correct the lsb
		}
		return(r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}	
	/************************/
	
	/**
	 * Compares two points for equality
	 * Overrides java's .equals
	 */
	@Override
	public boolean equals(Object o) {
		if(this == o) {
			return true;
		}
		else if(o == null) {
			return false;
		}
		else if(this.getClass() != o.getClass()) {
			return false;
		}
		
		Ecurve temp = (Ecurve) o;
		if(temp.X == this.X && temp.Y == this.Y) {
			return true;
		}
		return false;
	}
	
	/**
	 * Gets opposite of a given point
	 * (x,y) -> (-x,y)
	 */
	public Ecurve opposite() {
		BigInteger newX = this.X.negate().mod(MersenneP);//Remember to mod:modualr arithmetic
		return new Ecurve(newX, this.Y);
	}
	
	/**
	 * Sums two points using the given E-curve equation:
	 * (x1,y1) + (x2, y2) = (x1y1+y1x2/1+dx1x2y1y2, y1y2-x1x2/1-dx1x2y1y2)
	 */
	public Ecurve sum(Ecurve a) {
		//d*x1*x2*y1*y2 mod p, recall mod arithmetic
		BigInteger term = this.X.multiply(a.X).multiply(this.Y.multiply(a.Y)).mod(MersenneP);//this term is used fairly often
		
		BigInteger denomX = BigInteger.ONE.add(d.multiply(term)).mod(MersenneP);
		BigInteger denomY = BigInteger.ONE.subtract(d.multiply(term)).mod(MersenneP);
		BigInteger numX = this.X.multiply(a.Y).add(this.Y.multiply(a.X)).mod(MersenneP);
		BigInteger numY = this.Y.multiply(a.Y).subtract(this.X.multiply(a.X)).mod(MersenneP);
		
		//use mod inverse to divide
		return new Ecurve(numX.multiply(denomX.modInverse(MersenneP)).mod(MersenneP), numY.multiply(denomY.modInverse(MersenneP)).mod(MersenneP));
	}	
	
	/**
	 * Multiply by scalar/exponentiation algorithm
	 */
	public Ecurve exponentiation(BigInteger s) {
		int k = s.bitLength();
		//Ecurve V = new Ecurve(this.X, this.Y); //this wasn't working correctly
		Ecurve V = new Ecurve(BigInteger.ZERO, BigInteger.ONE);//initialize V so that its the neutral point, 0,1
		
		for(int i = k-1; i >= 0 ; i--) {
			V = V.sum(V);
			if(s.testBit(i)){
				V = V.sum(this);
			}
		}
		
		return V;
	}
	
	public BigInteger getX() {
		return X;
	}
	public BigInteger getY() {
		return Y;
	}

	/**
	 * Used to return a point as bytes
	 * @return
	 */
	public byte[] toBytes() {
		//The two points as bytes
		byte[] x = X.toByteArray(); 
        byte[] y = Y.toByteArray();
	    byte[] r = new byte[MersenneP.toByteArray().length * 2];

	    byte corrector = (byte) 0xff;
        if (X.signum() < 0) {
        	Arrays.fill(r, 0, (MersenneP.toByteArray().length * 2) / 2 - x.length, corrector);
        }
        if (Y.signum() < 0) {
        	Arrays.fill(r, (MersenneP.toByteArray().length * 2) / 2, r.length - y.length, corrector);
        }        
        System.arraycopy(x, 0, r, (MersenneP.toByteArray().length * 2) / 2 - x.length, x.length);
        System.arraycopy(y, 0, r, r.length - y.length, y.length);
        return r;
	}

	/**
	 * Undoes a byte array by translating it into an ecurve
	 * @param z
	 * @return
	 */
	public static Ecurve unByte(byte[] z) {
        BigInteger a = new BigInteger(Arrays.copyOfRange(z, 0, (MersenneP.toByteArray().length * 2) / 2));
        BigInteger b = new BigInteger(Arrays.copyOfRange(z, (MersenneP.toByteArray().length * 2) / 2, (MersenneP.toByteArray().length * 2)));

        return new Ecurve(a, b);
    }
}