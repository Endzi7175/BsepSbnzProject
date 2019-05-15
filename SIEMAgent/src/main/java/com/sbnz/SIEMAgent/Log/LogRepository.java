package com.sbnz.SIEMAgent.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;


@Component
public class LogRepository {

    private Set<Log> logs;
    private String fileName;
    public  LogRepository(){
        fileName = "logRepo.data";
    }
    private Gson gson;
    private  Gson getGSON (){
        if(gson==null){
            gson = new GsonBuilder().enableComplexMapKeySerialization().setPrettyPrinting() .create();
        }
        return  gson;
    }

    Log findByPath(String path)
    {
        Optional<Log> log = findAll()
                .stream()
                .filter(l-> l.path.equals(path))
                .findFirst();
        return log.orElse(null);
    }

    public void save(Log log) {
        logs.add(log);
        writeAll();
    }


    public Set<Log> findAll() {
        if (logs==null){
            logs =readAll();
        }
        return  logs;

    }

    private  Set<Log> readAll()
    {
        Set<Log> rets = new HashSet<>();
        try ( FileReader fr = new FileReader(fileName)){
            String json = new String(Files.readAllBytes(Paths.get(fileName)), StandardCharsets.UTF_8);
            return  getGSON().fromJson(json, new TypeToken<HashSet<Log>>(){}.getType());

        } catch (IOException e) {
            e.printStackTrace();
        }
        return rets;
    }

    private  void writeAll()
    {
        try (OutputStreamWriter fstream =  new OutputStreamWriter(new FileOutputStream(fileName), StandardCharsets.UTF_8)) {
            Set<PosixFilePermission> perms = new HashSet<>();

            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.OWNER_EXECUTE);

            Files.setPosixFilePermissions(Paths.get(fileName), perms);
            fstream.write(getGSON().toJson(logs));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Greska prilikom otvaranja fajla.");
        }
    }
}
