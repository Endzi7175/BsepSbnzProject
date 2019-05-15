import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

public class NormalState extends State{

	@Override
	public void createLogs(Logger logger) {
		Random r = new Random();
		System.out.println("Generating logs in normal state...");
		for (int i = 0; i < 50; i++){
			int random = r.nextInt(5);
			if (random == 0){
				logger.write("Pogresna lozinka", generateRandomUser(), 'S', 'H', generateRandomIpAddress(), generateInformationSystemCode());
			}else if (random == 1){
				logger.write("Uspesna prijava", generateRandomUser(), 'S', 'L', generateRandomIpAddress(), generateInformationSystemCode());
			}else if (random == 2){
				logger.write("Izmena profila", generateRandomUser(), 'S', 'M', generateRandomIpAddress(), generateInformationSystemCode());
			}else if (random == 3){
				String user = generateRandomUser();
				String ip = generateRandomIpAddress();
				logger.write("Antivirus registruje pretnju", user, 'S', 'H', ip, generateInformationSystemCode());
				logger.write("Otklonjena pretnja", user,  'S', 'L', ip, generateInformationSystemCode());
			}
			
		}
	}
	public static void main(String[] args){
		State s = new NormalState();
		Logger logger = new Logger();
		logger.setFile("mylog.log");
		s.createLogs(logger);
	}

}
