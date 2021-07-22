/**
 * This special class is used to return a cryptogram of mixed types(Ecurve and byte arrays)
 * when encrypting
 * @author Andrew Josten
 *
 */
public class CurveGram {
	Ecurve Z;
	byte[] c;
	byte[]t;
	
	public CurveGram(Ecurve Z, byte[] c, byte [] t) {
		this.Z = Z;
		this.c = c;
		this.t = t;
	}
	
	public byte[] toArray(){
		return concat(Z.toBytes(), concat(c, t));
	}
	
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

	/**
	 * Transforms this cryptogram into a byte array to be printed to a file
	 * @return
	 */
	public byte[] toBytes() {
		return concat(Z.toBytes(), concat(c,t));
	}	
}
