package example;

public class DtlsServerConfig {
	private String hostname;
	private int port;
	private ClientAuth auth;
	private boolean enableResumption;
	
	// some default options
	public DtlsServerConfig() {
		this.hostname = "localhost";
		this.port = 20000;
		this.auth = ClientAuth.DISABLED;
		this.enableResumption = false;
	}
	
	public String getHostname() {
		return hostname;
	}

	public int getPort() {
		return port;
	}

	public ClientAuth getAuth() {
		return auth;
	}

	public boolean isResumptionEnabled() {
		return enableResumption;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}
	public void setPort(int port) {
		this.port = port;
	}
	public void setAuth(ClientAuth auth) {
		this.auth = auth;
	}
	public void setEnableResumption(boolean enableResumption) {
		this.enableResumption = enableResumption;
	}
	
	

}
