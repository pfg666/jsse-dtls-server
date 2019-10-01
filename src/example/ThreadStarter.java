package example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.function.Supplier;

/**
 * We use this class to avoid having to restart the vm (which is can be a slow process). 
 */
public class ThreadStarter {
	
	private Supplier<Thread> supplier;
	private ServerSocket srvSocket;
	private Thread dtlsServerThread;
	private Socket cmdSocket;
	private boolean ack;

	public ThreadStarter(Supplier<Thread> supplier, Integer ipPort, boolean ack) throws IOException {
		InetSocketAddress address = new InetSocketAddress("localhost", ipPort);
		this.supplier = supplier;
		srvSocket = new ServerSocket();
		srvSocket.setReuseAddress(true);
		srvSocket.setSoTimeout(20000);
		srvSocket.bind(address);
		this.ack = ack;
		
		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					ThreadStarter.this.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}));
	}
	
	public void run() throws IOException {
		System.out.println("Listening at " + srvSocket.getInetAddress() + ":" + srvSocket.getLocalPort());
		cmdSocket = srvSocket.accept();
		cmdSocket.setSoTimeout(20000);
		BufferedReader in = new BufferedReader(new InputStreamReader(cmdSocket.getInputStream()));
		BufferedWriter out = new BufferedWriter(new OutputStreamWriter(cmdSocket.getOutputStream()));
		dtlsServerThread = null;
		while (true) {
			try {
				String cmd = in.readLine();
				System.out.println("Received: " + cmd);
				if (cmd != null) {
					switch(cmd.trim()) {
					case "reset":
						if (dtlsServerThread != null) {
							dtlsServerThread.interrupt();
						}
						dtlsServerThread = supplier.get();
						dtlsServerThread.start();
						if (ack) {
							out.write("ack");
							out.newLine();
							out.flush();
						}
						break;
					case "exit":
						close();
						return;
					}
				} else {
					close();
					return;
				}
			} catch (IOException e) {
				close();
				return;
			}
		}
	}
	
	private void close() throws IOException {
		System.out.println("Sutting down thread starter");
		if (dtlsServerThread != null) {
			dtlsServerThread.interrupt();
		}
		if (cmdSocket != null) {
			cmdSocket.close();
		}
		srvSocket.close();
	}
}
