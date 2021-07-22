import java.util.Arrays;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * 
 * @author Andrew Josten
 * TCSS 487
 * Practical project –cryptographic library & app
 */

public class Main {
	static KmacFunctions kmac;
	static EcurveFunctions ec;	
	
	public static void main(String args[]) throws IOException {
		kmac = new KmacFunctions();
		ec = new EcurveFunctions();	
		
		Ecurve Ec = new Ecurve();
		Ec.exponentiation(BigInteger.valueOf(1729L));
				
		Scanner sc = new Scanner(System.in);
		String next = "";
		
		System.out.println("(See README/instruction pdf for use instructions)");
		System.out.println("Type 'q' to quit\n");
		System.out.println("Cryptographic App:\n******************");

		while(!next.equals("q")) {
			//Prompt
			System.out.print("\n[KMAC/EC] [Function]\n>");
			next = sc.nextLine();
			
			//Check if quit
			if(next.equals("q")) {
				break;
			}			
			
			String[] params = next.split("\\s+");
			if(params.length != 2) {
				System.out.println("Bad input: wrong number of parameters");
			}
			params[0] = params[0].toLowerCase();
			params[1] = params[1].toLowerCase();
			
			//main parser
			byte[] msg = new byte[] {};
			byte[] pw = new byte[] {};
			String outputFile = "out.txt";
			String[] fileArgs;
			
			if(params[0].equals("kmac")) {//KMAC functions
				//get msg and passphrase input (if not plain hash)
				if(params[1].equals("plainhash")) {
					System.out.print("[Message.txt] [Output.txt]\n>");
					next = sc.nextLine();
					fileArgs = next.split("\\s+");
					msg = readFile(fileArgs[0]);
					outputFile = fileArgs[1];
				}
				else if(params[1].equals("authentication") || params[1].equals("encrypt") || params[1].equals("decrypt")) {
					System.out.print("[Message.txt] [Passphrase.txt] [Output.txt]\n>");
					next = sc.nextLine();
					fileArgs = next.split("\\s+");
					msg = readFile(fileArgs[0]);
					pw = readFile(fileArgs[1]);
					outputFile = fileArgs[2];
				}
				else {
					System.out.println("Bad input: unrecognized function in 2nd arguement");
				}
				
				switch(params[1]) {
					case "plainhash":
						outFile(kmac.cryptographicHash(msg), outputFile);
						break;
					case "authentication":
						outFile(kmac.authenticationTag(msg, pw), outputFile);
						break;
					case "encrypt":
						outFile(kmac.encrypt(msg, pw), outputFile);
						break;
					case "decrypt":
						outFile(kmac.decrypt(msg, pw), outputFile);
						break;
				}
			}
			else if(params[0].equals("ec")){//EC functions
				switch(params[1]) {
					case "keypair":						
						System.out.println("(Following encryption/decryption will be done under this key pair unless called again)");
						System.out.print("[Passphrase.txt] [Output.txt]\n>");
						next = sc.nextLine();
						fileArgs = next.split("\\s+");
						msg = readFile(fileArgs[0]);
						outputFile = fileArgs[1];
						ec.KeyPair(msg);
						
						byte[] kp = concat(ec.getV().toBytes(), ec.getS().toByteArray());
						outFile(kp, outputFile);
						break;
					case "encrypt":
						System.out.print("(Uses previously generated keypair)\n[Message.txt] [Output.txt]\n>");
						next = sc.nextLine();
						fileArgs = next.split("\\s+");
						msg = readFile(fileArgs[0]);
						outputFile = fileArgs[1];
						
						CurveGram g = ec.encrypt(msg);

						outFile(g.toBytes(), outputFile);
						break;
					case "decrypt":
						System.out.print("[Cryptogram.txt] [Passphrase.txt] [Output.txt]\n>");
						next = sc.nextLine();
						fileArgs = next.split("\\s+");
						msg = readFile(fileArgs[0]);
						pw = readFile(fileArgs[1]);
						outputFile = fileArgs[2];						
						
						//parse curve gram
						Ecurve Z = Ecurve.unByte(Arrays.copyOfRange(msg, 0, BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE).toByteArray().length*2));
				        byte[] a = Arrays.copyOfRange(msg, BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE).toByteArray().length*2, msg.length - 64);
				        byte[] b = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
				        
				        outFile(ec.decrypt(new CurveGram(Z,a,b), pw), outputFile);
						break;
					case "sign":
						System.out.print("[Message.txt] [Passphrase.txt] [Output.txt]\n>");
						next = sc.nextLine();
						fileArgs = next.split("\\s+");
						msg = readFile(fileArgs[0]);
						pw = readFile(fileArgs[1]);
						outputFile = fileArgs[2];
						outFile(ec.sigGenerator(pw, msg), outputFile);
						break;
					case "verify":
						System.out.print("[Signature.txt] [MessageByteArray.txt]\n>");
						next = sc.nextLine();
						fileArgs = next.split("\\s+");
						msg = readFile(fileArgs[0]);
						pw = readFile(fileArgs[1]);
						
						//parse sig
						byte[][] hz = new byte[2][];
						hz[0] = Arrays.copyOfRange(msg, 0, 130/2);
						hz[1] = Arrays.copyOfRange(msg, 130/2, 130);
						
						if(ec.verify(hz, pw)) {
							System.out.println("Signature is verified!");
						}
						else {
							System.out.println("Signature failed");
						}
						break;
					default:
						System.out.println("Bad input: unrecognized function in 2nd arguement");
				}
			}
			else {
				System.out.println("Bad input: unrecognized algorithm type");
			}
		}
		System.out.println("Quitting...");		
		sc.close();
	}
	
	/**
	 * Reads a file and converts its contents to a byte array to be used in crypto functions
	 * @param string
	 * @throws IOException 
	 */
	private static byte[] readFile(String name) throws IOException {
		FileInputStream bytesOut = null;
		byte[] r = null;
		
		try {
			File file = new File(name);
			r = new byte[(int) file.length()];
			bytesOut = new FileInputStream(file);
			bytesOut.read(r);
			//System.out.println(Arrays.toString(r));
        } 
		catch (FileNotFoundException e) {
            System.out.println("File not found");
        }
		
        return r;
	}
	
	/**
	 * Outputs to a file.
	 * @param out
	 * @param name
	 * @throws IOException
	 */
	private static void outFile(byte[] out, String name) throws IOException {
		FileOutputStream bytesOut = null;
		try {
            bytesOut = new FileOutputStream(name);//the file we are writing to
            bytesOut.write(out);
            System.out.println("File " + name + " successfully written to.");
        } 
		catch (FileNotFoundException e) {
            System.out.println("File not found");
        }
	}

	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}	
}