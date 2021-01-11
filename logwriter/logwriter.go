package logwriter

import (
    "os"
    "fmt"
    "log"
    "time"
    "strings"
)

const capacity = 32768

type LogWriter struct {
    logFilePath string
    buffer []byte
    position int
    channel chan []byte
    saveBufferEveryNSeconds time.Duration 
}

// Creates and return a new LogWriter structure
func NewLogWriter(_logFilePath string, _channel chan []byte, _period time.Duration) *LogWriter {
    return &LogWriter{
        logFilePath: _logFilePath,
        buffer: make([]byte, capacity),
        channel: _channel,
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
            case event := <- lw.channel:
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
        file, err := os.OpenFile(lw.logFilePath, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0666)
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