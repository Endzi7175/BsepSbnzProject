package com.sbnz.SIEMAgent;




import com.sbnz.SIEMAgent.FileWatcher.WatchAgent;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

import java.nio.file.Paths;


@SpringBootApplication
@EnableAsync
@ComponentScan
public class SiemAgentApplication implements CommandLineRunner {
	
	  private final org.slf4j.Logger logger = LoggerFactory.getLogger(SiemAgentApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SiemAgentApplication.class, args);
	}

	@Autowired
	WatchAgent agent;


	@Override
	public void run(String... args) throws Exception {

		agent.loadWatchers();
		try {
			agent.registerNewPath(Paths.get("D:\\3. godina\\WORKSPACE_ECLIPSE\\LogSimulator"),0);
		} catch (WatchAgent.WatchAgentException e) {
			e.printStackTrace();
		}

	}



}
