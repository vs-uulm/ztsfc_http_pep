package logwriter

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"os"
	"strings"
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

var Log_writer *LogWriter

type LogWriter struct {
	Logger  *logrus.Logger
	logfile *os.File
}

// Creates and return a new LogWriter structure
func New(_log_file_path, _log_level string, _ifTextFormatter bool) *LogWriter {
	var err error
	Log_writer = new(LogWriter)

	// Create a new instance of logrus logger
	Log_writer.Logger = logrus.New()

	// Set a log level (debug, info, warning, error)
	switch strings.ToLower(_log_level) {
	case "debug":
		Log_writer.Logger.SetLevel(logrus.DebugLevel)
	case "info":
		Log_writer.Logger.SetLevel(logrus.InfoLevel)
	case "warning":
		Log_writer.Logger.SetLevel(logrus.WarnLevel)
	case "error":
		Log_writer.Logger.SetLevel(logrus.ErrorLevel)
	case "":
		Log_writer.Logger.SetLevel(logrus.ErrorLevel)
	default:
		log.Fatal("Wrong log level value. Supported values are info, warning, error (default)")
	}

	// Set a JSON log formatter if necessary
	if _ifTextFormatter {
		Log_writer.Logger.SetFormatter(&logrus.TextFormatter{})
	} else {
		Log_writer.Logger.SetFormatter(&logrus.JSONFormatter{})
	}

	if strings.ToLower(_log_file_path) == "stdout" {
		Log_writer.Logger.SetOutput(os.Stdout)
	} else {
		// Open a file for the logger output
		Log_writer.logfile, err = os.OpenFile(_log_file_path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}

		// Redirect the logger output to the file
		Log_writer.Logger.SetOutput(Log_writer.logfile)
	}

	return Log_writer
}

// Function for calling by http.Server ErrorLog
func (lw LogWriter) Write(p []byte) (n int, err error) {
	// Customization of the line to be logged
	output := string(p)
	if !strings.Contains(output, ",success") {
		if strings.HasSuffix(output, "\n") {
			output = strings.TrimSuffix(output, "\n")
        }
//		if strings.HasSuffix(output, "\n") {
//			output = strings.TrimSuffix(output, "\n") + ",denied"
	//	} else {
	//		output = output + ",denied"
	//	}
		lw.Logger.WithFields(logrus.Fields{"result": "denied"}).Info(output)
	} else {
        output = strings.TrimSuffix(output, ",success")
		lw.Logger.WithFields(logrus.Fields{"result": "success"}).Info(output)
	}
	return 1, nil
}

// The LogHTTPRequest() function prints HTTP request details into the log file
// TODO Rename the function!
func (lw *LogWriter) LogHTTPRequest(req *http.Request) {
    // TODO: MAKE THIS BETTER
	lw.Write([]byte(fmt.Sprintf("%s,%s,%s,%t,%t,%s,success",
		req.RemoteAddr,
		req.TLS.ServerName,
		MatchTLSConst(req.TLS.Version),
		req.TLS.HandshakeComplete,
		req.TLS.DidResume,
		MatchTLSConst(req.TLS.CipherSuite))))
}

func (lw *LogWriter) Terminate() {
	lw.logfile.Close()
}

func MatchTLSConst(input uint16) string {
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
	// TLS CIPHER SUITES
	// TODO: Replace it by func CipherSuiteName --> version 1.14 needed
	case 0x0005:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case 0x000a:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x002f:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x003c:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x009c:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009d:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0xc007:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case 0xc009:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case 0xc00a:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0x5600:
		return "TLS_FALLBACK_SCSV"
	default:
		return "unsupported"
	}
}
