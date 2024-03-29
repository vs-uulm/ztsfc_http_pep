package init

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

func initBlocklists(sysLogger *logger.Logger) error {
	if err := initBotnetBlocklist(sysLogger); err != nil {
		return fmt.Errorf("initBlocklist(): %v", err)
	}

	return nil
}

func initBotnetBlocklist(sysLogger *logger.Logger) error {
	if config.Config.Blocklists.PathToBotnetList == "" {
		return errors.New("InitBlocklist(): path to botnet blocklist is not defined")
	}

	botnetListData, err := os.ReadFile(config.Config.Blocklists.PathToBotnetList)
	if err != nil {
		return fmt.Errorf("InitBotnetBlocklist(): could not read file '%s' at given path to botnet blocklist", config.Config.Blocklists.PathToBotnetList)
	}

	arrOfBotnetIPs := strings.Split(string(botnetListData), "\n")
	if len(arrOfBotnetIPs) == 1 {
		sysLogger.Infof("init: InitBlocklist(): initBotnetBlocklist(): botnet blocklist contains only one entry. is this correct?")
	}

	config.Config.Blocklists.BotnetList = make(map[string]struct{})

	for _, ip := range arrOfBotnetIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		config.Config.Blocklists.BotnetList[ip] = struct{}{}
	}

	go reloadRoutine(sysLogger)

	return nil
}

func reloadRoutine(sysLogger *logger.Logger) {
	reloadInterval := time.Tick(1 * time.Minute)
	for range reloadInterval {
		err := reloadBotnetList(sysLogger)
		if err == nil {
			sysLogger.Info("init: reloadRoutine(): successfully updated botnet blocklist")
		} else {
			sysLogger.Infof("init: reloadRoutine(): %v: updating the botnet blocklist failed... trying again in 5 minutes", err)
		}
	}
}

func reloadBotnetList(sysLogger *logger.Logger) error {
	botnetListData, err := os.ReadFile(config.Config.Blocklists.PathToBotnetList)
	if err != nil {
		return fmt.Errorf("reloadBotnetList(): %v", err)
	}

	newBotnetList := make(map[string]struct{})
	arrOfBotnetIPs := strings.Split(string(botnetListData), "\n")

	for _, ip := range arrOfBotnetIPs {
		if net.ParseIP(ip) == nil {
			continue
		}

		if _, exist := newBotnetList[ip]; exist {
			continue
		} else {
			newBotnetList[ip] = struct{}{}
		}
	}

	config.Config.Blocklists.WaitBotnetList.Add(1)
	config.Config.Blocklists.BotnetList = newBotnetList
	config.Config.Blocklists.WaitBotnetList.Add(-1)

	return nil
}
