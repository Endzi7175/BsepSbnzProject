package com.sbnz.SIEMAgent.AgentConfig;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
public class AgentProperties {

    @Column
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    long id;

    @Column
    long batchTime;

    @Column
    @ElementCollection(fetch=FetchType.EAGER )
    List<String> watchDirectiories;

    @Column
    @OneToMany(cascade = CascadeType.ALL, mappedBy="id", fetch=FetchType.EAGER )
    Map<String, DataRegex> regex;

    public long getBatchTime() {
        return batchTime;
    }

    public void setBatchTime(long batchTime) {
        this.batchTime = batchTime;
    }

    public  AgentProperties(){
        watchDirectiories = new ArrayList<>();
        regex = new HashMap<>();
    }

    public List<String> getWatchDirectiories() {
        return watchDirectiories;
    }

    public void setWatchDirectiories(List<String> watchDirectiories) {
        this.watchDirectiories = watchDirectiories;
    }

    public Map<String, DataRegex> getRegex() {
        return regex;
    }

    public void setRegex(Map<String, DataRegex> regex) {
        this.regex = regex;
    }

    public void assign(AgentProperties agentProperties) {
        this.batchTime = agentProperties.batchTime;
        this.regex = agentProperties.regex;
        this.watchDirectiories = agentProperties.watchDirectiories;
    }
}
