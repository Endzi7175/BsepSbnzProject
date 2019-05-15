package com.sbnz.SIEMAgent.AgentConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class AgentPropertiesService
{
    @Autowired
    AgentPropertiesRepository repository;



    private  static AgentProperties instance;


    public AgentProperties getProperties(){
        if(instance!=null){
            return  instance;
        }
        if(!repository.findById(1L).isPresent()){
            instance = new AgentProperties();
            repository.save(instance);
            repository.flush();
        } else {
            instance = repository.findById(1L).get();
        }

        return instance;
    }

    public void editProperties(AgentProperties agentProperties)
    {
        if(instance==null){
            getProperties();
        }
        instance.assign(agentProperties);
        AgentProperties ap = repository.findById(instance.id).get();

        repository.save(ap);
    }

    public void addWatchDirectory(String path)
    {
        if(getProperties().getWatchDirectiories().contains(path)){
            return;
        }
        instance.getWatchDirectiories().add(path);
        instance.getRegex().put(path + "/(.*)", new DataRegex());
        repository.save(instance);
        System.err.println("Added new path: " + path);
    }


}
