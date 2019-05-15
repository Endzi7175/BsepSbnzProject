import java.util.Random;

public abstract class State {
	public abstract void createLogs(Logger logger);
	
	
	protected String generateRandomIpAddress(){
		Random r = new Random();
		return r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256);
	}
	
	protected String generateRandomUser(){
		Random r = new Random();
		return "User" + r.nextInt(999);
	}
	protected int generateInformationSystemCode(){
		Random r = new Random();
		return r.nextInt(3);
	}

}
