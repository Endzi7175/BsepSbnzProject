import java.util.Scanner;

public class Simulator {
	State state;
	public void changeState(State s){
		this.state = s;
	}
	

	public State getState() {
		return state;
	}


	public void setState(State state) {
		this.state = state;
	}


	public static void main(String[] args){
		Scanner keyboard = new Scanner(System.in);
		Simulator sim = new Simulator();
		Logger logger = new Logger();
		int stateCode = 1;
		do{
			System.out.println("Choose state: \n1 - Normal state\n2 - Attack state\n9 - exit");
			stateCode = keyboard.nextInt();
			if (stateCode == 1){
				sim.changeState(new NormalState());
				logger.setFile("normal.log");
				sim.getState().createLogs(logger);
				logger.getWriter().close();

			}else if(stateCode == 2){
				sim.changeState(new AttackState());
				logger.setFile("attack.log");
				sim.getState().createLogs(logger);
				logger.getWriter().close();
			}else{
				System.out.println("Invalid option!");
			}
		}while(stateCode != 9);
		keyboard.close();
	}
}
