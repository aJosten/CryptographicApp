import java.util.Arrays;

/**
 * Derived from C example and the office-hour walk-through
 * As well as the Keccek team's github:
 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
 * 
 * https://keccak.team/keccak_specs_summary.html
 * 
 * @author Andrew Josten
 *
 */
public class SHA3 {
	// state context
	public byte[/*200*/] st;// = new byte[200];					// 64-bit words
	public int pt, rsiz, mdlen; 	// these don't overflow
    
	// constants used in keccak
	public static final long keccakf_rndc[] = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
	public static final int keccakf_rotc[] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
	public static final int keccakf_piln[] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

	//For the KMAC implementation we use 24 rounds
	public static final int KECCAKF_ROUNDS = 24;
	
	public static long ROTL64(long x, int y) {
		return ((x << y) | (x >>> (-y)));
	}
	
	/**
	 * The keccak sponge. Derived from keccak home page and its c and python examples
	 * https://keccak.team/keccak_specs_summary.html
	 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
	 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
	 */
	public byte[] Keccak(int rate, int capacity, byte[] X, int outputBitLen) {		
		//Padding
		if(X.length % (rate / 8) != 0) {
	        int zSize = (rate / 8) - X.length % (rate / 8);//zSize:how much we're padding
	        byte[] temp = new byte[X.length + zSize];
	        
	        for (int i = 0; i < X.length + zSize; i++) {
	            if (i < X.length) {
	            	temp[i] = X[i];
	            }
	            else if (i==X.length + zSize - 1) {
	            	temp[i] = (byte) 128; 
	            }
	            else {
	            	temp[i] = 0;
	            }
	        }
	        X = temp;
		}
		
        //Absorbing.
        long[][] keccakModel = new long[(X.length * 8) / rate ][25];
        int off = 0;
        for (int i = 0; i < keccakModel.length; i++) {
            long[] dataLane = new long[25];
            for (int j = 0; j < rate / 64; j++) {
            	long temp = 0L;
                for (int k = 0; k < 8; k++) {
                	temp += (( (long) X[off + k]) & 255)<<(8 * k);
                }
                
                dataLane[j] = temp;
                off += 8;
            }
            keccakModel[i] = dataLane;
        }
        
        long[] lane = new long[25];
        for (long[] st : keccakModel) {//for each block, Pi in P, xor (see keccak page)
        	long[] S = new long[25];
            for (int i = 0; i < lane.length; i++) {
                S[i] = lane[i] ^ st[i];
            }
            lane = keccakPerms(S); 
        }

        //Squeezing
        long[] squeezes = {};
        int inputOffset = 0;
        int r = rate / 64;
        do {
            squeezes = Arrays.copyOf(squeezes, inputOffset + r);
            System.arraycopy(lane, 0, squeezes, inputOffset, r);
            lane = keccakPerms(lane);
            inputOffset += r;
        } while (squeezes.length * 64 < outputBitLen);//while output is requested
        
        //State was represented in a 2d array object. Reverting to array
        byte[] Z = new byte[outputBitLen/8];
        int laneIndex = 0;
        
        while (laneIndex*64 < outputBitLen) {
        	//System.out.println(laneIndex + " ");
            long newLane = squeezes[laneIndex++];
            
            int seq = 8;
            if(64 * laneIndex > outputBitLen){
            	seq = (outputBitLen - (laneIndex - 1) * 64) / 8;
            }
            
            for (int i = 0; i < seq; i++) {
                byte retByte = (byte) (newLane >>>(8 * i) & 255);
                Z[(laneIndex - 1)*8 + i] = retByte;
            }
        }

        return Z;
	}

	/**
	 * The main permutation loop
	 * Derived from a combination of tiny_sha3 as well as Keccak's c and python implementations.
	 * (Partially cannibalized from minisha3, sha3_keccakf)
	 * At a recomendation from 
	 * https://keccak.team/keccak_specs_summary.html
	 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
	 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
	 * 
	 * @param v
	 * @return
	 */
	private static long[] keccakPerms(long[] v) {
	    long[] state = v;
	    for (int rounds = 0; rounds < KECCAKF_ROUNDS; rounds++) {	        
	        //Theta
	        long[] x = new long[25];
	        long[] C = new long[5];
	        long D;
	        
	        for (int i = 0; i < 5; i++) {
	            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
	        }
	        for (int i = 0; i < 5; i++) {
	            D = C[(i + 4) % 5] ^ ROTL64(C[(i+1) % 5], 1);

	            for (int j = 0; j < 5; j++) {
	            	x[i + 5*j] = state[i + 5*j] ^ D;
	            }
	        }
	        state = x;
	        
	        //rho pi
	        x = new long[25];
	        x[0] = state[0];
	        long t = state[1];
	        long row;
	        int count;
	        
	        for (int i = 0; i < 24; i++) {
	            count = keccakf_piln[i];
	            row = state[count];
	            x[count] = ROTL64(t, keccakf_rotc[i]);
	            t = row;
	        }
	        state = x;
	        
	        //chi
	        x = new long[25];
	        for (int i = 0; i < 5; i++) {
	            for (int j = 0; j < 5; j++) {
	                long bc = ~state[(i+1) % 5 + 5 * j] & state[(i+2) % 5 + 5*j];
	                x[i + 5 * j] = state[i + 5 * j] ^ bc;
	            }
	        }
	        state = x;
	        
	        //iota
	        state[0] ^= keccakf_rndc[rounds]; 
	    }
	    return state;
	}
	    
	
	
	
	/*THE FOLLOWING CODE IS NOT USED*/
	
	    /*
	     * The following code is from the tinysha3 repo. I had troubles getting it to work and decided to 
	     * implement an algorithm based on the keccak home page's psuedocode instead. I left the tinysha3 for posterity
	     * */

	    // Initialize the context for SHA3
		void sha3_init(int _mdlen){
			st = new byte[200];
		    for (int i = 0; i < 25; i++) {
		        st[i] = (byte) 0;
		    }
		    mdlen = _mdlen;
		    //rsiz = 200 - 2 * (mdlen/8);//note: figure this out
		    rsiz = 1088/8;
		    pt = 0;
		}
	
		// update state with more data.
		void sha3_update(byte[] data, int len){
			
		    int j = pt;	    
		    for (int i = 0; i < len; i++) {
		    	System.out.println(j + " " +  rsiz);
		    	
		        st[j++] ^= data[i];
		        if (j >= rsiz) {
		            //sha3_keccakf(st);
		            j = 0;
		        }
		    }
		    pt = j;
		}	
	
		// finalize and output a hash
		public byte[] sha3_final() {
			byte [] md = new byte[mdlen];
			
		    st[pt] ^= 0x06;
		    st[rsiz - 1] ^= 0x80;
		    //sha3_keccakf(st);
	
		    for (int i = 0; i < mdlen; i++) {
		        md[i] = st[i];
		    }
		    return md;
		}
	
		// SHAKE128 and SHAKE256 extensible-output functionality
		void shake_xof(){
		    st[pt] ^= 0x1F; //(oxo4)
		    st[rsiz - 1] ^= 0x80;
		    //sha3_keccakf(st);
		    pt = 0;
		}
		
		//?
		void shake_out(byte[] out, int len)
		{
		    int j = pt;
		    for (int i = 0; i < len; i++) {
		        if (j >= rsiz) {
		            //sha3_keccakf(st);
		            j = 0;
		        }
		        out[i] = st[j++];
		    }
		    pt = j;
		}

}