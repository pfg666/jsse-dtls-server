/* * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved. * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER. * * This code is free software; you can redistribute it and/or modify it * under the terms of the GNU General Public License version 2 only, as * published by the Free Software Foundation. * * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * Adapted from: 
 * http://cr.openjdk.java.net/~asmotrak/8159416/webrev.08/test/javax/net/ssl/DTLS/DTLSOverDatagram.java.html
 * 
 * An up-to-date version of this code is at:
 * https://hg.openjdk.java.net/jdk/jdk/file/00ae3b739184/test/jdk/javax/net/ssl/DTLS/DTLSOverDatagram.java
 * 
 * Very useful is the option.
 * -Djavax.net.debug=all
 */
package example;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;


/**
 * A basic DTLS echo server built around JSSE's SSLEngine. 
 */
public class DtlsServer {

	private static int LOG_LEVEL = 1; // 0 no logging, 1 basic logging, 2 logging incl. method name
	{
		String level = System.getProperty("log.level");
		if (level != null)
			LOG_LEVEL = Integer.valueOf(level);
	}
	private static final int MAX_HANDSHAKE_LOOPS = 200;
	private static final int MAX_APP_READ_LOOPS = 60;
	private static final int BUFFER_SIZE = 20240;

	/*
	 * The following is to set up the keystores.
	 */
	private static final String keyFilename = "rsa2048.jks";
	private static final String keyPasswd = "student";
	private static final String trustFilename = "rsa2048.jks";
	private static final String trustPasswd = "student";

	private InetSocketAddress peerAddr;
	private SSLContext currentContext;

	/*
	 * A mock DTLS echo server which uses SSLEngine.
	 */
	void runServer(DatagramSocket socket, InetSocketAddress clientSocketAddr, ClientAuth auth,
			boolean withSessionResumption) throws Exception {
		peerAddr = clientSocketAddr;

		// create SSLEngine
		SSLEngine engine = createSSLEngine(false, auth, false);

		ByteBuffer appData = null;
		doFullHandshake(engine, socket);
		// read server application data
		while (true) {
			// ok, the engine is closed, if resumption was enabled we create a new engine,
			// otherwise we exit.
			if (isEngineClosed(engine) ) {
				if (withSessionResumption) {
					engine = createSSLEngine(false, auth, withSessionResumption);
					doFullHandshake(engine, socket);
				} else 
					break;
			} else {
				if (engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
					doHandshakeStepCatchExceptions(engine, socket);
				} else {
					appData = receiveAppData(engine, socket);

					if (appData != null) {
						info("Server received application data");

						// write server application data
						sendAppData(engine, socket, appData.duplicate(), peerAddr, "Server");
					}
				}
			}
		}
	}

	private static boolean isEngineClosed(SSLEngine engine) {
		return (engine.isOutboundDone() && engine.isInboundDone());
	}

	/* 
	 * basic SSL Engine
	 */
	private SSLEngine createSSLEngine(boolean isClient, ClientAuth auth, boolean withResumption) throws Exception {
		SSLContext context;
		if (withResumption && currentContext != null)
			context = currentContext;
		else
			context = getDTLSContext();
		currentContext = context;

		SSLEngine engine = context.createSSLEngine();
		engine.setUseClientMode(isClient);

		if (!isClient) {
			switch (auth) {
			case WANTED:
				engine.setWantClientAuth(true);
				break;
			case NEEDED:
				engine.setNeedClientAuth(true);
				break;
			default:
				break;
			}
		}

		return engine;
	}

	/*
	 * Executes a full handshake, may or may not succeed.
	 * 
	 * The code is messy, what is important is that we do everything the SSLEngine tells us.
	 * There are essentially 4 commands an SSLEngine can issue (associated with the HandshakeStatus):
	 * 1. unwrap - meaning the engine is expecting to receive network data. 
	 * This data should be received and inputed to the engine.
	 * 2. wrap - meaning the engine has network data ready.
	 * This data should be gathered from the engine and sent.
	 * 3. execute task - meaning the engine requests execution of some tasks.
	 * We should just execute them.
	 * 4. finished handshaking - the engine is done with the current handshake.  
	 * That might mean that the handshake was completed successfully.
	 * Either that or invalid messages rendered the engine unable to continue with the handshake.
	 * 
	 * In the latter case, we expect the engine to be in a closed state, hence we instantiate a new engine.
	 * If resumption is enabled, we use the same context 
	 * 
	 * Wrap and unwrap operations return results which also should be considered.
	 * 
	 */
	private void doFullHandshake(SSLEngine engine, DatagramSocket socket) throws Exception {

		boolean isDone = false;
		int loops = MAX_HANDSHAKE_LOOPS;
		engine.beginHandshake();
		while (!isDone && !isEngineClosed(engine)) {

			if (--loops < 0) {
				throw new RuntimeException("Exhausted the maximum number of loops allowed");
			}
			
			isDone = doHandshakeStepCatchExceptions(engine, socket);
		}
		
		if (isDone) {
			SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
			info("Handshake finished, status is " + hs);
	
			if (engine.getHandshakeSession() != null) {
				throw new Exception("Handshake finished, but handshake session is not null");
			}
	
			SSLSession session = engine.getSession();
			if (session == null) {
				throw new Exception("Handshake finished, but session is null");
			}
			info("Negotiated protocol is " + session.getProtocol());
			info("Negotiated cipher suite is " + session.getCipherSuite());
	
			// handshake status should be NOT_HANDSHAKING
			//
			// according to the spec,
			// SSLEngine.getHandshakeStatus() can't return FINISHED
			if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
				throw new Exception("Unexpected handshake status " + hs);
			}
		}
	}
	
	private boolean doHandshakeStepCatchExceptions(SSLEngine engine, DatagramSocket socket) {
		try {
			return doHandshakeStep(engine, socket);
		} catch(Exception exc) {
			severe("Exception while executing handshake step");
			exc.printStackTrace();
			severe("Continuing to flush causative problem");
			return false;
		} 
	}

	// returns true if the handshake operation is completed/engine is closed, and false otherwise
	private boolean doHandshakeStep(SSLEngine engine, DatagramSocket socket) throws Exception {
		SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
		info("handshake status: " + hs);
		List<DatagramPacket> packets;
		switch (hs) {
		// SSLEngine is expecting network data from the outside
		case NEED_UNWRAP:
		case NEED_UNWRAP_AGAIN:
			info("expecting DTLS records");
			ByteBuffer iNet;
			ByteBuffer iApp;
			if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
				byte[] buf = new byte[BUFFER_SIZE];
				DatagramPacket packet = new DatagramPacket(buf, buf.length);
				try {
					info("waiting for a packet");
					receivePacket(packet, socket);
					info("received a packet of length = " + packet.getLength());
				} catch (SocketTimeoutException ste) {
					info("socket timed out");
					return false;
				}

				iNet = ByteBuffer.wrap(buf, 0, packet.getLength());
				iApp = ByteBuffer.allocate(BUFFER_SIZE);
			} else {
				iNet = ByteBuffer.allocate(0);
				iApp = ByteBuffer.allocate(BUFFER_SIZE);
			}

			SSLEngineResult r = engine.unwrap(iNet, iApp);
			SSLEngineResult.Status rs = r.getStatus();

			logResult("unwrap", r);
			switch (rs) {
			case OK:
				break;
			case BUFFER_OVERFLOW:
			case BUFFER_UNDERFLOW:
				throw new Exception("Unexpected buffer error: " + rs);
			case CLOSED:
				engine.closeInbound();
				return true;
			default:
				throw new Exception("This branch should not be reachable");
			}
			break;

		// SSLEngine wants to send network data to the outside world
		case NEED_WRAP:
			info("preparing to send DTLS records");
			packets = new ArrayList<>();
			produceHandshakePackets(engine, peerAddr, packets);

			for (DatagramPacket p : packets) {
				socket.send(p);
			}
			break;

		// SSLEngine wants some tasks to be executed.
		case NEED_TASK:
			runDelegatedTasks(engine);
			break;

		// SSLEngine has finished handshaking
		case NOT_HANDSHAKING:
			info("finished handshaking");
			return true;

		case FINISHED:
			throw new Exception("Unexpected status, SSLEngine.getHandshakeStatus() " + "shouldn't return FINISHED");
		}

		return false;
	}

	// deliver application data
	private void sendAppData(SSLEngine engine, DatagramSocket socket, ByteBuffer appData, SocketAddress peerAddr, String side)
			throws Exception {

		List<DatagramPacket> packets = produceApplicationPackets(engine, appData, peerAddr);
		appData.flip();
		info("sending " + packets.size() + " packets");
		for (DatagramPacket p : packets) {
			socket.send(p);
		}
	}

	private ByteBuffer receiveAppData(SSLEngine engine, DatagramSocket socket) throws Exception {
		int loops = MAX_APP_READ_LOOPS;
		while (true) {
			if (--loops < 0) {
				throw new RuntimeException("Too many loops to receive application data");
			}

			byte[] buf = new byte[BUFFER_SIZE];
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			info("waiting for a packet");
			try {
				receivePacket(packet, socket);
				info("received a packet of length " + packet.getLength());
			} catch (SocketTimeoutException e) {
				severe(e.getMessage());
				continue;
			}

			ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());
			ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
			SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);
			logResult("unwrap",rs);
			recBuffer.flip();
			if (recBuffer.remaining() != 0) {
				return recBuffer;
			}
			if (rs.getStatus() == Status.CLOSED) {
				engine.closeInbound();
			}
			if (engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
				return null;
			}
		}
	}

	// receive packet and update peer address while you are at it
	private void receivePacket(DatagramPacket packet, DatagramSocket socket) throws IOException {
		socket.receive(packet);
		InetSocketAddress peerAddress = (InetSocketAddress) packet.getSocketAddress();
		if (peerAddr == null || !peerAddress.equals(peerAddr)) {
			info("setting peer address to " + peerAddr);
			peerAddr = (InetSocketAddress) packet.getSocketAddress();
		}
	}

	// produce handshake packets
	private void produceHandshakePackets(SSLEngine engine, SocketAddress socketAddr, List<DatagramPacket> packets)
			throws Exception {

		int loops = MAX_HANDSHAKE_LOOPS;
		while (engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {

			if (--loops < 0) {
				throw new RuntimeException("Too many loops to produce handshake packets");
			}

			ByteBuffer oNet = ByteBuffer.allocate(32768);
			ByteBuffer oApp = ByteBuffer.allocate(0);
			SSLEngineResult r = engine.wrap(oApp, oNet);
			oNet.flip();

			logResult("wrap", r);
			Status rs = r.getStatus();

			switch (rs) {
			case BUFFER_UNDERFLOW:
			case BUFFER_OVERFLOW:
				throw new Exception("Unexpected buffer error: " + rs);
			case CLOSED:
			case OK:
				if (oNet.hasRemaining()) {
					byte[] ba = new byte[oNet.remaining()];
					oNet.get(ba);
					DatagramPacket packet = createHandshakePacket(ba, socketAddr);
					packets.add(packet);
				}
				break;
			default:
				throw new Exception("This branch should not be reachable " + rs);
			}

		}

		info("produced " + packets.size() + " packets");
	}

	// produce application packets
	private List<DatagramPacket> produceApplicationPackets(SSLEngine engine, ByteBuffer source, SocketAddress socketAddr)
			throws Exception {

		List<DatagramPacket> packets = new ArrayList<>();
		ByteBuffer appNet = ByteBuffer.allocate(32768);
		SSLEngineResult r = engine.wrap(source, appNet);
		appNet.flip();
		logResult("wrap", r);
		SSLEngineResult.Status rs = r.getStatus();
		switch(rs) {
		case BUFFER_OVERFLOW:
		case BUFFER_UNDERFLOW:
			throw new Exception("Unexpected buffer error: " + rs);
		case OK:
			if (appNet.hasRemaining()) {
				byte[] ba = new byte[appNet.remaining()];
				appNet.get(ba);
				DatagramPacket packet = new DatagramPacket(ba, ba.length, socketAddr);
				packets.add(packet);
			}
			break;
		case CLOSED:
			throw new Exception("SSLEngine has closed unexpectedly");
		default:
			throw new Exception("This branch should not be reachable " + rs);
		}

		return packets;
	}
	

	private void logResult(String operation, SSLEngineResult result) {
		info(operation + " result: " + result);
	}

	private DatagramPacket createHandshakePacket(byte[] ba, SocketAddress socketAddr) {
		return new DatagramPacket(ba, ba.length, socketAddr);
	}

	// run delegated tasks
	private void runDelegatedTasks(SSLEngine engine) throws Exception {
		Runnable runnable;
		while ((runnable = engine.getDelegatedTask()) != null) {
				runnable.run();
		}

		SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
		if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
			throw new Exception("handshake shouldn't need additional tasks");
		}
	}

	// get DTSL context
	private SSLContext getDTLSContext() throws Exception {
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
		System.err.println(sslCtx.getProvider());

		sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		System.err.println(Arrays.asList(sslCtx.getDefaultSSLParameters().getCipherSuites()));
		
		return sslCtx;
	}

	static void severe(String message) {
		log(System.err, message);
	}

	static void info(String message) {
		log(System.out, message);
	}

	static void log(PrintStream ps, String message) {
		if (LOG_LEVEL > 0) {
			if (LOG_LEVEL > 1) {
				String methodName = Arrays.stream(Thread.currentThread().getStackTrace()).skip(3)
						.filter(e -> !e.getMethodName().startsWith("log")).findFirst().get().getMethodName();
				ps.println(methodName + ": " + message);
			} else {
				ps.println(message);
			}
		}
	}

	static void sleep(long millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

//  
//
//	/*
//	 * This is a much cleaner version of a handshake, but needs a bit more time to be made functional. 
//	 * Adapted from: 
//	 * https://github.com/alkarn/sslengine.example
//	 *  
//	 */
//
//	protected boolean doHandshake(SSLEngine engine, DatagramSocket socket) throws IOException {
//        info("About to do handshake...");
//
//        SSLEngineResult result;
//        HandshakeStatus handshakeStatus;
//
//        ByteBuffer myAppData = ByteBuffer.allocate(BUFFER_SIZE);
//        ByteBuffer peerAppData = ByteBuffer.allocate(BUFFER_SIZE);
//        ByteBuffer myNetData = ByteBuffer.allocate(BUFFER_SIZE);
//        ByteBuffer peerNetData = ByteBuffer.allocate(BUFFER_SIZE);
//        engine.beginHandshake();
//
//        handshakeStatus = engine.getHandshakeStatus();
//        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
//            switch (handshakeStatus) {
//            case NEED_UNWRAP:
//            case NEED_UNWRAP_AGAIN:
//            	byte[] buf = new byte[BUFFER_SIZE];
//            	peerNetData.clear();
//				DatagramPacket packet = new DatagramPacket(buf, buf.length);
//				try {
//					info("waiting for a packet");
//					receivePacket(packet, socket);
//					peerNetData.put(packet.getData());
//					info("received a packet, length = " + packet.getLength());
//				} catch (SocketTimeoutException ste) {
//					info("socket timed out, do nothing");
//					handshakeStatus = engine.getHandshakeStatus();
//                    break;
//				}
//				if (isEngineClosed(engine)) {
//					return false;
//				}
//                peerNetData.flip();
//                try {
//                    result = engine.unwrap(peerNetData, peerAppData);
//                    peerNetData.compact();
//                    handshakeStatus = result.getHandshakeStatus();
//                } catch (SSLException sslException) {
//                    severe("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
//                    engine.closeOutbound();
//                    handshakeStatus = engine.getHandshakeStatus();
//                    break;
//                }
//                switch (result.getStatus()) {
//                case OK:
//                    break;
//                case BUFFER_OVERFLOW:
//                case BUFFER_UNDERFLOW:
//                	severe("Unhandled cases" + result.getStatus());
//                    break;
//                case CLOSED:
//                    if (engine.isOutboundDone()) {
//                        return false;
//                    } else {
//                        engine.closeOutbound();
//                        handshakeStatus = engine.getHandshakeStatus();
//                        break;
//                    }
//                default:
//                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
//                }
//                break;
//            case NEED_WRAP:
//                myNetData.clear();
//                try {
//                    result = engine.wrap(myAppData, myNetData);
//                    handshakeStatus = result.getHandshakeStatus();
//                } catch (SSLException sslException) {
//                    severe("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
//                    engine.closeOutbound();
//                    handshakeStatus = engine.getHandshakeStatus();
//                    break;
//                }
//                switch (result.getStatus()) {
//                case OK :
//                    myNetData.flip();
//                    sendData(myNetData, socket, peerAddr);
//                    break;
//                case BUFFER_OVERFLOW:
//                case BUFFER_UNDERFLOW:
//                    throw new SSLException("Unexpected buffer under/overflow cases");
//                case CLOSED:
//                    try {
//                        myNetData.flip();
//                        sendData(myNetData, socket, peerAddr);
//                    } catch (Exception e) {
//                        severe("Failed to send server's CLOSE message due to socket channel's failure.");
//                        handshakeStatus = engine.getHandshakeStatus();
//                    }
//                    break;
//                default:
//                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
//                }
//                break;
//            case NEED_TASK:
//                Runnable task;
//                while ((task = engine.getDelegatedTask()) != null) {
//                	task.run();
//                }
//                handshakeStatus = engine.getHandshakeStatus();
//                break;
//            case FINISHED:
//                break;
//            case NOT_HANDSHAKING:
//                break;
//            default:
//                throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
//            }
//        }
//
//        return true;
//
//	}
//	
//	
//	private void sendData(ByteBuffer bufferedData, DatagramSocket socket, SocketAddress address) throws IOException {
//		while (bufferedData.hasRemaining()) {
//			byte[] buf = new byte[bufferedData.remaining()];
//			bufferedData.get(buf);
//			DatagramPacket packet = createHandshakePacket(buf, address);
//			socket.send(packet);
//		}
//	}
//	
}
