package logging

import (
	"fmt"
	"log"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
)

// Logger is an interface that defines the logging methods
type Logger interface {
	Info(msg string)
	Error(msg string)
	Debug(msg string)
}

// ZapLogger is a struct that implements the Logger interface using zap
type ZapLogger struct {
	logger *zap.Logger
}

// Info logs a message at info level
func (z *ZapLogger) Info(msg string) {
	z.logger.Info(msg)
}

// Error logs a message at error level
func (z *ZapLogger) Error(msg string) {
	z.logger.Error(msg)
}

// Error logs a message at error level
func (z *ZapLogger) Debug(msg string) {
	z.logger.Debug(msg)
}

// logr.logger
type LogrLogger struct {
	logger *logr.Logger
}

// Info logs a message at info level
func (r *LogrLogger) Info(msg string) {
	r.logger.Info(msg)
}

// Error logs a message at error level
func (r *LogrLogger) Error(msg string) {
	r.logger.Error(fmt.Errorf("an error"), msg)
}

func (r *LogrLogger) Debug(msg string) {
	r.logger.Info(msg)
}

// log.logger
type LogLogger struct {
	logger *log.Logger
}

// Info logs a message at info level
func (l *LogLogger) Info(msg string) {
	prefix := fmt.Sprintf("%v :", "Info")
	l.logger.SetPrefix(prefix)
	l.logger.Println(msg)
}

// Error logs a message at error level
func (l *LogLogger) Error(msg string) {
	prefix := fmt.Sprintf("%v :", "Error")
	l.logger.SetPrefix(prefix)
	l.logger.Println(msg)
}

// Debug logs a message at debug level
func (l *LogLogger) Debug(msg string) {
	prefix := fmt.Sprintf("%v :", "Debug")
	l.logger.SetPrefix(prefix)
	l.logger.Println(msg)
}

// NewZapLogger creates a new ZapLogger with the given zap.Logger
func NewZapLogger(logger *zap.Logger) *ZapLogger {
	return &ZapLogger{logger: logger}
}

// NewLogrLogger creates a new logrLogger with the given logr.logger
func NewLogrLogger(logger *logr.Logger) *LogrLogger {
	return &LogrLogger{logger: logger}
}

func NewLogLogger(logger *log.Logger) *LogLogger {
	return &LogLogger{logger: logger}
}
