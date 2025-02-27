// Copyright 2024 BeyondTrust. All rights reserved.
// Package logging abstraction.
// Unit tests for logging package.
package logging

import (
	"bytes"
	"log"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogging(t *testing.T) {

	var zapBuffer bytes.Buffer
	zapCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.AddSync(&zapBuffer),
		zapcore.DebugLevel,
	)
	zapLogger := zap.New(zapCore)

	var logrBuffer bytes.Buffer
	loggerLogger := funcr.New(func(prefix, args string) {
		logrBuffer.WriteString(args + "\n")
	}, funcr.Options{})

	var goBuffer bytes.Buffer
	goLogger := log.New(&goBuffer, "my:", log.LstdFlags)
	goLogger.SetOutput(&goBuffer)

	zapLoggerObj := NewZapLogger(zapLogger)
	goLoggerObj := NewLogLogger(goLogger)
	loggerLoggerObj := NewLogrLogger(&loggerLogger)

	zapLoggerObj.Info("Info Message using zap logger")
	zapLoggerObj.Error("Error Message using zap logger")
	zapLoggerObj.Debug("Debug Message using zap logger")
	zapLoggerObj.Warn("Warn Message using zap logger")

	loggerLoggerObj.Info("Info Message using logr logger")
	loggerLoggerObj.Error("Error Message using logr logger")
	loggerLoggerObj.Debug("Debug Message using logr logger")
	loggerLoggerObj.Warn("Warn Message using logr logger")

	goLoggerObj.Info("Info Message using go logger")
	goLoggerObj.Error("Error Message using go logger")
	goLoggerObj.Debug("Debug Message using go logger")
	goLoggerObj.Warn("Warn Message using go logger")

	zapOutput := zapBuffer.String()
	assert.Contains(t, zapOutput, `Info Message using zap logger"`)
	assert.Contains(t, zapOutput, `Error Message using zap logger"`)
	assert.Contains(t, zapOutput, `Debug Message using zap logger"`)
	assert.Contains(t, zapOutput, `Warn Message using zap logger"`)

	logrOutput := logrBuffer.String()
	assert.Contains(t, logrOutput, "Info Message using logr logger")
	assert.Contains(t, logrOutput, "Error Message using logr logger")
	assert.Contains(t, logrOutput, "Debug Message using logr logger")
	assert.Contains(t, logrOutput, "Error Message using logr logger")

	stdoutOutput := goBuffer.String()
	assert.Contains(t, stdoutOutput, "Info Message using go logger")
	assert.Contains(t, stdoutOutput, "Error Message using go logger")
	assert.Contains(t, stdoutOutput, "Debug Message using go logger")
	assert.Contains(t, stdoutOutput, "Warn Message using go logger")
}
