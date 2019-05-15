package com.sbnz.SIEMAgent.FileWatcher;

import com.google.gson.annotations.Expose;
import com.sbnz.SIEMAgent.Log.Log;
import com.sbnz.SIEMAgent.Log.LogService;

import javax.persistence.Transient;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class DirWatcher extends Thread{

    @Expose
    private String path;

    public Path getPath() {
        return Paths.get(path);
    }

    @Transient
    private WatchService watchService;

    @Expose
    private long batchTime;



    private LogService logService;

    public void setLogService(LogService logService){
        this.logService=logService;
    }

    @Expose
    private Map<String, List<DataFilter>> regex;

    public DirWatcher(String path, long batchTime, LogService logService){
        this.path = path;
        regex = new HashMap<>();
        this.logService = logService;
    }
    public DirWatcher(String path, LogService logService)
    {    this(path, 0, logService);
    }
    public DirWatcher(){
        this("", null);
    }

    @Override
    public void run() {
        WatchKey key = null;
        try {
            watchService = FileSystems.getDefault().newWatchService();
            getPath().register(
                    watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        while (true) {
            try {
                if(batchTime>0){
                    Thread.sleep(batchTime);
                    key = watchService.poll();
                } else {
                    key = watchService.take();
                }
            } catch (InterruptedException | ClosedWatchServiceException e) {
                    break;
            }
            if(key!=null){
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind().equals(StandardWatchEventKinds.ENTRY_MODIFY) || event.kind().equals(StandardWatchEventKinds.ENTRY_CREATE)) {
                        String fileName = event.context().toString();
                        Set<DataFilter> filters = getDataFilters(fileName);
                        Log log = logService.getLogByPath(Paths.get(path, fileName).toString());
                        logService.processNewEnteries(log, filters);
                    }
                }
                key.reset();
            }

        }
    }

    private Set<DataFilter> getDataFilters(String fileName)
    {
        Set<DataFilter> filters = new HashSet<>();
        if(regex.size()==0){
            return null;
        }
        for(String regexStr : regex.keySet()){
            if(fileName.matches(regexStr)){
                filters.addAll(this.regex.get(regexStr));
            }
        }
        return  filters;
    }

    @Override
    public void interrupt() {
        try {
            watchService.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.interrupt();
    }

    public void addRegxFilter(String regexFilename, DataFilter filter) {
        regex.putIfAbsent(regexFilename, new ArrayList<>());
        regex.get(regexFilename).add(filter);

    }
}
