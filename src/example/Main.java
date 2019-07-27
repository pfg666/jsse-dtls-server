package example;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.LinkedList;

/* ClassFileServer.java -- a simple file server that can server
 * Http get request in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that
 * reads files from the file system. See the
 * doc for the "Main" method for how to run this
 * server.
 */

public class Main {
	
	private static int SOCKET_TIMEOUT = 100000;
    
    /**
     * Creates an echo DTLS server. 
     * Accepts the following arguments:
     * <ul>
     * 	<li> the port on which the server accepts; </li>   
     * 	<li> whether client authentication is wanted/needed/disabled (optional); </li> 
     *  <li> session resumption enabled-ness (optional). </li>
     * </ul>
     * 
     * The socket timeout is set to a very high value on purpose. 
     * The DTLS server does not do anything on a timeout anyway.
     */
    public static void main(String args[])
    {
    	ClientAuth defAuth = ClientAuth.DISABLED;
    	boolean defSr = false;
    	if (args.length ==0) {
	        System.out.println(
	            "USAGE: java DtlsTestServer port [NEEDED|WANTED|DISABLED [resumption_enabled]]");
	        System.out.println("Default client auth is " + ClientAuth.DISABLED.name());
	        System.out.println("Default sr enabled-mess is " + defSr);
	        return;
    	}
    	
    	LinkedList<String> argList = new LinkedList<String>();
    	argList.addAll(Arrays.asList(args));

        int port = Integer.parseInt(argList.removeFirst());

        try {
        	ClientAuth auth = defAuth;
        	if (!argList.isEmpty()) {
        		String authString = argList.removeFirst();
            	auth = ClientAuth.valueOf(authString);
            }
        	boolean enabledSr = defSr;
        	if (!argList.isEmpty()) {
        		String srString = argList.removeFirst();
        		enabledSr = Boolean.valueOf(srString);
        	}
            
        	DtlsServer dtlsHarness = new DtlsServer();
        	InetSocketAddress address = new InetSocketAddress("localhost", port);
        	DatagramSocket socket = new DatagramSocket(address);
        	socket.setSoTimeout(SOCKET_TIMEOUT);
        	dtlsHarness.runServer(socket, null, auth, enabledSr);
        } catch (Exception e) {
            System.out.println("Got Exception: " +
                               e.getMessage());
            e.printStackTrace();
        } 
    }    
}