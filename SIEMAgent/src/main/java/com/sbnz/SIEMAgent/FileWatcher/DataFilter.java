package com.sbnz.SIEMAgent.FileWatcher;

import com.sbnz.SIEMAgent.Log.LogEntry;

import java.lang.reflect.Field;

import java.util.Set;


public interface DataFilter {
    public boolean applyFilter(LogEntry entry);
}



