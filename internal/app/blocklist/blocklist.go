package blocklist

import (
    "net/http"
    "net"

    "github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

/*
blocks requests according to the defined blocklists in config

@return bool: true if request must be blocked, else false
*/
func BlockRequest(req *http.Request) bool {
    host, _, err := net.SplitHostPort(req.RemoteAddr)
    if err != nil {
        return true
    }

    config.Config.Blocklists.WaitBotnetList.Wait()
    _, ok := config.Config.Blocklists.BotnetList[host]
    if ok {
        return true
    } else {
        return false
    }
}
