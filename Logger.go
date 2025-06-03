package golangJwtAuth

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Logger struct {
	DebugLogger  *log.Logger
	OutputLogger *log.Logger
	ErrorLogger  *log.Logger
	Path         string
}

func newLogger(path string) (*Logger, error) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	initLog, initErr := openLog(path, "debug.log")
	outputLog, actionErr := openLog(path, "output.log")
	errorLog, actionErr := openLog(path, "error.log")

	if initErr != nil || actionErr != nil {
		return nil, fmt.Errorf("failed to open log files: init=%v, action=%v",
			initErr, actionErr)
	}

	return &Logger{
		DebugLogger:  log.New(io.MultiWriter(initLog, os.Stdout), "", log.LstdFlags),
		OutputLogger: log.New(io.MultiWriter(outputLog, os.Stdout), "", log.LstdFlags),
		ErrorLogger:  log.New(io.MultiWriter(errorLog, os.Stdout), "", log.LstdFlags),
		Path:         path,
	}, nil
}

func openLog(path string, target string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(path, target), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", target, err)
	}
	return file, nil
}

func writeToLog(target *log.Logger, level string, message ...string) {
	level = strings.ToUpper(level)
	isValid := map[string]bool{
		"DEBUG":    true,
		"TRACE":    true,
		"INFO":     true,
		"NOTICE":   true,
		"WARNING":  true,
		"ERROR":    true,
		"FATAL":    true,
		"CRITICAL": true,
	}[level]

	if len(message) == 0 || !isValid {
		return
	}

	state := ""
	switch level {
	case "INFO":
		state = ""
	default:
		state = fmt.Sprintf("[%s] ", level)
	}

	for i, msg := range message {
		if i == 0 {
			target.Printf("%s%s", state, message[i])
		} else if i == len(message)-1 {
			target.Printf("└── %s", msg)
		} else {
			target.Printf("├── %s", msg)
		}
	}
}

func (l *Logger) Debug(message ...string) {
	writeToLog(l.DebugLogger, "DEBUG", message...)
}

func (l *Logger) Trace(message ...string) {
	writeToLog(l.DebugLogger, "TRACE", message...)
}

func (l *Logger) Info(message ...string) {
	writeToLog(l.OutputLogger, "INFO", message...)
}

func (l *Logger) Notice(message ...string) {
	writeToLog(l.OutputLogger, "NOTICE", message...)
}

func (l *Logger) Warning(message ...string) {
	writeToLog(l.OutputLogger, "WARNING", message...)
}

func (l *Logger) Error(message ...string) error {
	writeToLog(l.ErrorLogger, "ERROR", message...)
	return fmt.Errorf("%s", strings.Join(message, " "))
}

func (l *Logger) Fatal(message ...string) error {
	writeToLog(l.ErrorLogger, "FATAL", message...)
	return fmt.Errorf("%s", strings.Join(message, " "))
}

func (l *Logger) Critical(message ...string) error {
	writeToLog(l.ErrorLogger, "CRITICAL", message...)
	return fmt.Errorf("%s", strings.Join(message, " "))
}
