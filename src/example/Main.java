package example;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.LinkedList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/* Main file which processes arguments and stuff. 
 */

public class Main {

	/**
     * Creates an echo DTLS server.
     *  
     * Accepts the following arguments:
     * <ul>
     * 	<li> the port on which the server accepts; </li>   
     * 	<li> whether client authentication is wanted/needed/disabled (optional); </li>
     *  <li> mode of operation: basic (single handshake, no application data exchange) 
     *  or full (loop with handshake and echoing received application data) (optional); </li>
     *  <li> retransmission enabled-ness (optional); </li> 
     *  <li> session resumption enabled-ness (optional); </li>
     *  <li> the port for the ThreadStarter launching the DTLS server otherwise 
     *  the server is launched once directly. ; </li>
     * </ul>
     * 
     */
    public static void main(String args[])
    {
    	DtlsServerConfig config = new DtlsServerConfig();
    	if (args.length ==0) {
	        System.out.println(
	            "USAGE: java Main ip:port [NEEDED|WANTED|DISABLED [operation [retransmission_enabled[ resumption_enabled [starter_port [acknowledge]]]]]]");
	        System.out.println("Default client auth is " + ClientAuth.DISABLED.name());
	        return;
    	}
    	
    	LinkedList<String> argList = new LinkedList<String>();
    	argList.addAll(Arrays.asList(args));

    	String ipPort = argList.removeFirst();
    	String[] ipPortArgs = ipPort.split("\\:");
    	config.setHostname(ipPortArgs[0]);
    	config.setPort(Integer.valueOf(ipPortArgs[1]));
    	
        String threadStarterIpPort = null;

        try {
        	if (!argList.isEmpty()) {
            	config.setAuth(ClientAuth.valueOf(argList.removeFirst()));
            }
        	if (!argList.isEmpty()) {
        		config.setOperation(Operation.valueOf(argList.removeFirst()));
        	}
        	if (!argList.isEmpty()) {
        		config.setEnableRetransmission(Boolean.valueOf(argList.removeFirst()));
        	}
        	if (!argList.isEmpty()) {
        		config.setEnableResumption(Boolean.valueOf(argList.removeFirst()));
        	}
        	if (!argList.isEmpty()) {
        		threadStarterIpPort = argList.removeFirst();
        	}

        	sslContext = getDTLSContext();
            
	        if (threadStarterIpPort == null) {
	        	DtlsServer dtlsHarness = new DtlsServer(config, sslContext);
	        	dtlsHarness.run();
        	} else {
        		// the server port is dynamically alocated in this case
        		config.setPort(0);
        		ThreadStarter ts = new ThreadStarter(() -> newServer(config, sslContext), threadStarterIpPort);
        		ts.run();
        	}
        	
        } catch (Exception e) {
            System.out.println("Exception: " +
                               e.getMessage());
            e.printStackTrace();
        } 
    }
    
	private static DtlsServer newServer(DtlsServerConfig config, SSLContext sslContext) {
		try {
			return new DtlsServer(config, sslContext);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}
	
	/*
	 * The following is to set up the keystores.
	 */
	private static final String keyFilename = "rsa2048.jks";
	private static final String keyPasswd = "student";
	private static final String trustFilename = "rsa2048.jks";
	private static final String trustPasswd = "student";
	
	private static SSLContext sslContext;
	
	// get DTSL context
	static SSLContext getDTLSContext() throws GeneralSecurityException, IOException {
		KeyStore ks = KeyStore.getInstance("JKS");
		KeyStore ts = KeyStore.getInstance("JKS");

		try (FileInputStream fis = new FileInputStream(keyFilename)) {
			ks.load(fis, keyPasswd.toCharArray());
		}

		try (FileInputStream fis = new FileInputStream(trustFilename)) {
			ts.load(fis, trustPasswd.toCharArray());
		}

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, keyPasswd.toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(ts);

		SSLContext sslCtx = SSLContext.getInstance("DTLS");
		sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		return sslCtx;
	}
	
}
