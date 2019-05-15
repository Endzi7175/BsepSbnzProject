
public class AttackState extends State{

	@Override
	public void createLogs(Logger logger) {
		System.out.println("Generating logs in attack state...");
		unsuccessfulAuthWithDifferentIpWithin10sec(logger);
		unsuccessfulAuthWithin5days(logger);
		generateErrorLog(logger);
		
	}
	private void unsuccessfulAuthWithin5days(Logger logger){
		String ipAddress = generateRandomIpAddress();
		String user = generateRandomUser();
		for (int i = 0; i < 20; i++){
			logger.write("Neuspesna prijava", user, 'S', 'H', ipAddress, generateInformationSystemCode());
		}
	}
	private void unsuccessfulAuthWithDifferentIpWithin10sec(Logger logger){
		String user = generateRandomUser();
		for (int i = 0; i < 15; i++){
			logger.write("Neuspesna prijava", user, 'S', 'H', generateRandomIpAddress(), generateInformationSystemCode());
		}
	}
	private void generateErrorLog(Logger logger){
		logger.write("Greska u programu", generateRandomUser(), 'E', 'H', generateRandomIpAddress(), generateInformationSystemCode());
		logger.write("Greska u programu", generateRandomUser(), 'E', 'H', generateRandomIpAddress(), generateInformationSystemCode());
		logger.write("Greska u programu", generateRandomUser(), 'E', 'H', generateRandomIpAddress(), generateInformationSystemCode());
	}
	
	
}
