package com.sbnz.SIEMAgent.AgentConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AgentPropertiesController {

    @Autowired
    AgentPropertiesService agentPropertiesService;


    @PostMapping (value =  "/dir")
    public ResponseEntity<?> addWatchDirectory(String path)
    {

        return  new ResponseEntity<>(HttpStatus.OK);
    }
}
