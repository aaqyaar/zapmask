package zapmask

import (
	"os"
	"regexp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
    pinRegex      = regexp.MustCompile(`pin=\d+`)
    passwordRegex = regexp.MustCompile(`password=\w+`)
)

// maskSensitiveData masks sensitive information in the log message.
func maskSensitiveData(input string) string {
    masked := pinRegex.ReplaceAllString(input, "pin=****")
    masked = passwordRegex.ReplaceAllString(masked, "password=****")
    return masked
}

// maskingCore is a custom zapcore.Core that masks sensitive information.
type maskingCore struct {
    zapcore.Core
}

// With implements the zapcore.Core interface.
func (c *maskingCore) With(fields []zapcore.Field) zapcore.Core {
    return &maskingCore{Core: c.Core.With(fields)}
}

// Check implements the zapcore.Core interface.
func (c *maskingCore) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
    if c.Enabled(entry.Level) {
        return checkedEntry.AddCore(entry, c)
    }
    return checkedEntry
}

// Write implements the zapcore.Core interface.
func (c *maskingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
    entry.Message = maskSensitiveData(entry.Message)
    return c.Core.Write(entry, fields)
}

// NewMaskedLogger creates a new zap.Logger with sensitive data masking enabled.
func NewMaskedLogger(config zap.Config) (*zap.Logger, error) {
    encoderConfig := zap.NewProductionEncoderConfig()
    encoder := zapcore.NewJSONEncoder(encoderConfig)

    core := &maskingCore{Core: zapcore.NewCore(encoder, zapcore.AddSync(zapcore.Lock(os.Stdout)), zap.DebugLevel)}
    return zap.New(core), nil
}
