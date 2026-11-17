package com.logsentry.parser;

import com.logsentry.model.LogEntry;

public interface LogParser {
    LogEntry parse(String rawLine);
}