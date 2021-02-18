package logwriter

import (
    "net/http"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const capacity = 32768

const (
	NONE = iota
	BASIC
	ADVANCED
	DEBUG
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
    log_level               int
	logFilePath             string
	buffer                  []byte
	position                int
	channel                 chan []byte
	saveBufferEveryNSeconds time.Duration
}

// Creates and return a new LogWriter structure
func NewLogWriter(_log_level int, _logFilePath string, _channel chan []byte, _period time.Duration) *LogWriter {
	return &LogWriter{
        log_level:               _log_level,
		logFilePath:             _logFilePath,
		buffer:                  make([]byte, capacity),
		channel:                 _channel,
		saveBufferEveryNSeconds: _period,
	}
}

// Main goroutine for reading messages from the channel and writing them to the log file
func (lw *LogWriter) Work() {
	// Infinite loop
	for {
		// Wit for channel event or timeout
		select {
		// Incoming event, read string from the channel
		case event := <-lw.channel:
			length := len(event)

			// Message is tooooo long
			if length > capacity {
				log.Println("message received was too large")
				continue
			}

			// Not enough free space in the buffer to store the message
			if (length + lw.position) > capacity {
				// Flush the buffer to the log file and clear it
				lw.Save()
			}

			// Append new message to the buffer content
			copy(lw.buffer[lw.position:], event)

			// Shift the buffer pointer
			lw.position += length

		// Flush the buffer to the log file periodically
		case <-time.After(lw.saveBufferEveryNSeconds * time.Second):
			lw.Save()
		} // select
	} // for
} // Work()

// Save the log buffer content to the log file and clear the buffer
func (lw *LogWriter) Save() {
	// Save only if buffer is not empty
	if lw.position != 0 {
		// Open the log file
		file, err := os.OpenFile(lw.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal("[LogWriter.Save] Error: ", err)
		}

		defer file.Close()

		// Save the buffer content to the file
		fmt.Fprintf(file, "%s", lw.buffer[0:lw.position])

		// "clear" the buffer
		lw.position = 0
	}
}

// Function for calling by http.Server ErrorLog
func (lw LogWriter) Write(p []byte) (n int, err error) {
	// Customization of the line to be logged
	output := string(p)
	if !strings.Contains(output, ",success") {
		if strings.HasSuffix(output, "\n") {
			output = strings.TrimSuffix(output, "\n") + ",denied\n"
		} else {
			output = output + ",denied\n"
		}
	}

	// Push the line to the log channel
	lw.channel <- []byte(output)

	return 1, nil
}

// The Log() function writes messages from a provided slice as space-separated string into the log
func (lw *LogWriter) Log(messages ...string) {
	// Nothing to do, if message's log level is lower than those, user has set
	if lw.log_level < 0 {
		return
	}

	// Creates a comma-separated string out of the incoming slice of strings
	s := lw.GetLogTimeStamp()
	for _, message := range messages {
		s = s + "," + message
	}

	// Send the resulhe buting string to the logging channel
	lw.channel <- []byte(s)
}

// The LogHTTPRequest() function prints HTTP request details into the log file
func (lw *LogWriter) LogHTTPRequest(req *http.Request) {
	// Check if we have something to do
	if lw.log_level < 0 {
		return
	}

	// Fill in the string with the rest data
	s := fmt.Sprintf("%s,%s,%s,%t,%t,%s,success\n",
		req.RemoteAddr,
		req.TLS.ServerName,
		MatchTLSConst(req.TLS.Version),
		req.TLS.HandshakeComplete,
		req.TLS.DidResume,
		MatchTLSConst(req.TLS.CipherSuite))

	// Write the string to the log file
	lw.Log(s)
}

func (lw LogWriter) GetLogTimeStamp() string {
	// Get current time
	t := time.Now()

	// Format time stamp
	ts := fmt.Sprintf("%4d/%02d/%02d %02d:%02d:%02d",
		t.Year(),
		t.Month(),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second())
	return ts
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
