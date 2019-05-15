package com.sbnz.SIEMAgent.AgentConfig;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
public class DataRegex {
    @Id
    @Column
    @GeneratedValue
    long id;

    @ElementCollection
    List<String> regex;

    public DataRegex(List<String> asList) {
        regex = asList;
    }
    public  DataRegex(){
        regex = new ArrayList<>();
    }
    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public List<String> getRegex() {
        return regex;
    }

    public void setRegex(List<String> regex) {
        this.regex = regex;
    }


}
