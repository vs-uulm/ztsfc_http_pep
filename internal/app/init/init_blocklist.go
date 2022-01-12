package init

import (
    "fmt"
    "errors"
    "net"
    "strings"
    "io/ioutil"

    "github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
    logger "github.com/vs-uulm/ztsfc_http_logger"
)

func InitBlocklists(sysLogger *logger.Logger) error {
    if err := initBotnetBlocklist(sysLogger); err != nil {
        return fmt.Errorf("init: InitBlocklist(): %v", err)
    }

    return nil
}

func initBotnetBlocklist(sysLogger *logger.Logger) error {
    if config.Config.Blocklists.PathToBotnetList == "" {
        return errors.New("InitBlocklist(): path to botnet blocklist is not defined")
    }

    //return fmt.Errorf("init: InitServicePoolParams(): unable to parse a target service URL for service function '%s': %w", sfName, err)

    botnetListData, err := ioutil.ReadFile(config.Config.Blocklists.PathToBotnetList)
    if err != nil {
        fmt.Errorf("InitBotnetBlocklist(): could not read file at given path to botnet blocklist")
    }

    arrOfBotnetIPs := strings.Split(string(botnetListData), "\n")
    if len(arrOfBotnetIPs) == 1 {
        sysLogger.Debugf("init: InitBlocklist(): initBotnetBlocklist(): botnet blocklist contains only one entry. is this correct?")
    }

    config.Config.Blocklists.BotnetList = make(map[string]struct{})

    for _, ip := range arrOfBotnetIPs {
        if net.ParseIP(ip) == nil {
            continue
        }
        config.Config.Blocklists.BotnetList[ip] = struct{}{}
    }

    return nil
}
