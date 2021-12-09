// Package logwriter contains a custom wrapper for logrus
// (see https://github.com/Sirupsen/logrus).
// The exported object LW can be used globally for logging through the whole
// project.
package logwriter

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	SFLOGGER_REGISTER_PACKETS_ONLY uint32 = 1 << iota
	SFLOGGER_PRINT_GENERAL_INFO
	SFLOGGER_PRINT_HEADER_FIELDS
	SFLOGGER_PRINT_TRAILERS
	SFLOGGER_PRINT_BODY
	SFLOGGER_PRINT_FORMS
	SFLOGGER_PRINT_FORMS_FILE_CONTENT
	SFLOGGER_PRINT_TLS_MAIN_INFO
	SFLOGGER_PRINT_TLS_CERTIFICATES
	SFLOGGER_PRINT_TLS_PUBLIC_KEY
	SFLOGGER_PRINT_TLS_CERT_SIGNATURE
	SFLOGGER_PRINT_RAW
	SFLOGGER_PRINT_REDIRECTED_RESPONSE
	SFLOGGER_PRINT_EMPTY_FIELDS
)

// LW is a LogWriter instance for global logging across the PEP.
// Use it like LW.Logger.Info("this is a logging message") or
// LW.Logger.WithField("someField", 1).Debug("some message")
// @author:marie
type LogWriter struct {
	logger *logrus.Entry
}

// New() creates and returns a new logrus.Logger instance
func New(logFilePath, logLevel, logFormatter string, logFields logrus.Fields) (*LogWriter, error) {
	var (
		err   error
		level logrus.Level
	)

	// Create a new instance of the logrus logger
	l := logrus.New()

	// Set the system logger logging level
	level, err = logrus.ParseLevel(logLevel)
	if err != nil {
		l.Errorf("unable to set the logger level %s", logLevel)
		return nil, err
	}
	l.SetLevel(level)
	l.Debugf("system logger logging level is set to %s", logLevel)

	// Set the system logger formatter
	switch strings.ToLower(logFormatter) {
	case "text":
		l.SetFormatter(&logrus.TextFormatter{})
	case "json":
		l.SetFormatter(&logrus.JSONFormatter{})
	default:
		l.Errorf("unable to set logging level %s. Supported values are JSON (default) and text", logFormatter)
		return nil, err
	}

	// Set the os.Stdout or a file for writing the system log messages
	if strings.ToLower(logFilePath) == "stdout" {
		l.SetOutput(os.Stdout)
	} else {
		// Open a file for the logger output
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			l.Errorf("unable to open file %s to write logging messages", logFilePath)
			return nil, err
		}

		// Redirect the logger output to the file
		l.SetOutput(file)
	}

	// Create a LogWriter struct and bind it to the configured logger
	lw := &LogWriter{
		logger: l.WithFields(logFields),
	}
	return lw, nil
}

// Function for calling by http.Server or httputil.ReverseProxy ErrorLog
func (lw *LogWriter) Write(p []byte) (n int, err error) {
	// Customization of the line to be logged
	output := string(p)
	if !strings.Contains(output, ",success") {
		output = strings.TrimSuffix(output, "\n")
		lw.logger.WithFields(logrus.Fields{"result": "denied"}).Info(output)
	} else {
		output = strings.TrimSuffix(output, ",success")
		lw.logger.WithFields(logrus.Fields{"result": "success"}).Info(output)
	}
	return 1, nil
}

// The LogHTTPRequest() function prints HTTP request details into the log file
// TODO Rename the function!
func (lw *LogWriter) LogHTTPRequest(req *http.Request) {
	lw.Infof("%s,%s,%s,%t,%t,%s,success",
		req.RemoteAddr,
		req.TLS.ServerName,
		MatchTLSConst(req.TLS.Version),
		req.TLS.HandshakeComplete,
		req.TLS.DidResume,
		MatchTLSConst(req.TLS.CipherSuite))
}

// func (lw *LogWriter) Terminate() {
// 	lw.logfile.Close()
// }

func MatchTLSConst(input uint16) string {
	// Decode the input value into a name of the cipher suite
	name := tls.CipherSuiteName(input)

	// If the name after decoding fits the "0x****" format,
	// then the CipherSuiteName could not decode the input
	if len(name) == 6 && strings.HasPrefix(name, "0x") {
		switch input {
		// TLS VERSION
		case 0x0300:
			return "VersionSSL30"
		case 0x0301:
			return "VersionTLS10"
		case 0x0302:
			return "VersionTLS11"
		case 0x0303:
			return "VersionTLS12"
		case 0x0304:
			return "VersionTLS13"
		default:
			return "unsupported"
		}
	}
	return name
}

// Info() calls the corresponding function of the original logrus package
func (lw *LogWriter) Info(args ...interface{}) {
	lw.logger.Info(args...)
}

// Infof() calls the corresponding function of the original logrus package
func (lw *LogWriter) Infof(format string, args ...interface{}) {
	lw.logger.Infof(format, args...)
}

// Error() calls the corresponding function of the original logrus package
func (lw *LogWriter) Error(args ...interface{}) {
	lw.logger.Error(args...)
}

// Errorf() calls the corresponding function of the original logrus package
func (lw *LogWriter) Errorf(format string, args ...interface{}) {
	lw.logger.Errorf(format, args...)
}

// Fatal() calls the corresponding function of the original logrus package
func (lw *LogWriter) Fatal(args ...interface{}) {
	lw.logger.Fatal(args...)
}

// Fatalf() calls the corresponding function of the original logrus package
func (lw *LogWriter) Fatalf(format string, args ...interface{}) {
	lw.logger.Fatalf(format, args...)
}

// Debug() calls the corresponding function of the original logrus package
func (lw *LogWriter) Debug(args ...interface{}) {
	lw.logger.Debug(args...)
}

// Debugf() calls the corresponding function of the original logrus package
func (lw *LogWriter) Debugf(format string, args ...interface{}) {
	lw.logger.Debugf(format, args...)
}

// WithField() calls the corresponding function of the original logrus package
func (lw *LogWriter) WithField(key string, value interface{}) *logrus.Entry {
	return lw.logger.WithField(key, value)
}

// WithFields() calls the corresponding function of the original logrus package
func (lw *LogWriter) WithFields(fields logrus.Fields) *logrus.Entry {
	return lw.logger.WithFields(fields)
}

func (lw *LogWriter) GetWriter() *io.PipeWriter {
	return lw.logger.Writer()
}
