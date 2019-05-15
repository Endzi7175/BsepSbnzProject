package com.sbnz.SIEMAgent.FileWatcher;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sbnz.SIEMAgent.Log.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

@Component
public class WatchAgent {


	@Autowired
	private  LogService logService;


	private  List<DirWatcher> dirWatchers;


	public  WatchAgent() {
		dirWatchers = new ArrayList<>();
	}


	public synchronized void registerNewPath(Path path, long batchTime) throws WatchAgentException, IOException {

		if (dirWatchers.stream().anyMatch(dir->dir.getPath().equals(path))) {
			throw new WatchAgentException("Trying to register multiple keys for same path!");
		}
		DirWatcher watcher = new DirWatcher(path.toString(), batchTime, logService);
		dirWatchers.add(watcher);
		watcher.start();
		saveWatchers();
	}

	public synchronized void cancelPath(Path path) throws IOException {
		DirWatcher watcher = getDirWatcherByPath(path);
		if(watcher!=null){
			watcher.interrupt();
			dirWatchers.remove(watcher);
		}
		saveWatchers();
	}



	private DirWatcher getDirWatcherByPath(Path path){
		Optional<DirWatcher> watcher = dirWatchers.stream()
				.filter(dirWatcher -> dirWatcher.getPath().equals(path))
				.findFirst();
		return watcher.orElse(null);

	}

	public void addRegexFilter(Path path, String string, DataFilter filter)
	{
		DirWatcher watcher = getDirWatcherByPath(path);
		if(watcher!=null){
			watcher.addRegxFilter(string, filter);
		}
		saveWatchers();
	}

	public static class WatchAgentException extends Throwable {
		public WatchAgentException(String s) {
			super(s);
		}
	}

	private Gson watcherGson;
	private  Gson getWatcherGson(){
		if(watcherGson==null){
			watcherGson = new GsonBuilder().setPrettyPrinting().enableComplexMapKeySerialization().excludeFieldsWithoutExposeAnnotation().create();
		}
		return watcherGson;
	}
	private  static String fileName = "watchers.data";
	private void saveWatchers() {

		try (OutputStreamWriter fstream =  new OutputStreamWriter(new FileOutputStream(fileName), StandardCharsets.UTF_8)) {
			Set<PosixFilePermission> perms = new HashSet<>();
			//add owners permission
			perms.add(PosixFilePermission.OWNER_READ);
			perms.add(PosixFilePermission.OWNER_WRITE);
			perms.add(PosixFilePermission.OWNER_EXECUTE);


			Files.setPosixFilePermissions(Paths.get(fileName), perms);
			fstream.write(getWatcherGson().toJson(dirWatchers));
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Greska prilikom otvaranja fajla.");
		}
	}

	public   void loadWatchers(){
		try (FileReader fr = new FileReader(fileName)){
			String json = new String(Files.readAllBytes(Paths.get(fileName)), StandardCharsets.UTF_8);
			 dirWatchers=getWatcherGson().fromJson(json, new TypeToken<ArrayList<DirWatcher>>(){}.getType());
			 if (dirWatchers == null){
				 System.out.println("asd");
			 }
			 for(DirWatcher watcher : dirWatchers)
			 {
			 	watcher.setLogService(logService);
			 	watcher.start();
			 }
		} catch (IOException e) {
			if(e.getClass().equals(FileNotFoundException.class)){
				System.err.println(e.getMessage());

			} else {
				e.printStackTrace();
			}

		}
	}
}
