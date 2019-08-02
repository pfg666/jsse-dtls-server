package example;

import java.net.SocketException;
import java.util.Arrays;
import java.util.LinkedList;

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
     *  <li> session resumption enabled-ness (optional); </li>
     *  <li> the port for the ThreadStarter launching the DTLS server, otherwise 
     *  the server is launched once directly. </li>
     * </ul>
     * 
     */
    public static void main(String args[])
    {
    	boolean defSr = false;
    	if (args.length ==0) {
	        System.out.println(
	            "USAGE: java Main port [NEEDED|WANTED|DISABLED [resumption_enabled [starter_port]]]");
	        System.out.println("Default client auth is " + ClientAuth.DISABLED.name());
	        System.out.println("Default sr enabled-mess is " + defSr);
	        return;
    	}
    	
    	LinkedList<String> argList = new LinkedList<String>();
    	argList.addAll(Arrays.asList(args));
    	DtlsServerConfig config = new DtlsServerConfig();

        int port = Integer.parseInt(argList.removeFirst());
        Integer threadStarterPort = null;
        config.setPort(port);

        try {
        	if (!argList.isEmpty()) {
        		String authString = argList.removeFirst();
            	config.setAuth(ClientAuth.valueOf(authString));
            }
        	if (!argList.isEmpty()) {
        		String srString = argList.removeFirst();
        		config.setEnableResumption(Boolean.valueOf(srString));
        	}
        	if (!argList.isEmpty()) {
        		String tsString = argList.removeFirst();
        		threadStarterPort = Integer.valueOf(tsString);
        	}
            
        	if (threadStarterPort == null) {
	        	DtlsServer dtlsHarness = new DtlsServer(config);
	        	dtlsHarness.run();
        	} else {
        		ThreadStarter ts = new ThreadStarter(() -> newServer(config), threadStarterPort);
        		ts.run();
        	}
        	
        } catch (Exception e) {
            System.out.println("Got Exception: " +
                               e.getMessage());
            e.printStackTrace();
        } 
    }

	private static DtlsServer newServer(DtlsServerConfig config) {
		try {
			return new DtlsServer(config);
		} catch (SocketException e) {
			e.printStackTrace();
			return null;
		}
	}
}
