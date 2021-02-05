package main
// hello alex

import (
    "log"
    "net/http"
    "net/url"
    "flag"

    env "local.com/leobrada/ztsfc_http_pep/env"
    router "local.com/leobrada/ztsfc_http_pep/router"
    sf_info "local.com/leobrada/ztsfc_http_pep/sf_info"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
    log_level = flag.Int("l", 0, "Log level")
)

func loadServicePool(config env.Config_t) (service_pool map[string]sf_info.ServiceFunctionInfo) {
    service_pool = make(map[string]sf_info.ServiceFunctionInfo, len(env.Config.Service_pool))
    for service_name, service_config := range(env.Config.Service_pool) {
        service_url, err := url.Parse(service_config.Target_service_addr)
        if err != nil {
            log.Fatal("Creating Service Pool Critical Error: ", err)
        }
        service, err := sf_info.NewServiceInfo(
            service_name,
            service_url,
            service_config.Cert_shown_by_pep_to_service,
            service_config.Privkey_for_cert_shown_by_pep_to_service,
            service_config.Sni)
        if err != nil {
            log.Fatal("Creating Service Pool Critical Error: ", err)
        }
        service_pool[service_name] = service
    }
    return
}

func loadSfPool(config env.Config_t) (sf_pool map[string]sf_info.ServiceFunctionInfo) {
    sf_pool = make(map[string]sf_info.ServiceFunctionInfo, len(env.Config.Sf_pool))
    for sf_name, sf_config := range(env.Config.Sf_pool) {
        sf_url, err := url.Parse(sf_config.Target_sf_addr)
        if err != nil {
            log.Fatal("Creating Service Function Pool Critical Error: ", err)
        }
        sf, err := sf_info.NewServiceFunctionInfo(
            sf_name,
            sf_url,
            sf_config.Cert_shown_by_pep_to_sf,
            sf_config.Privkey_for_cert_shown_by_pep_to_sf)
        if err != nil {
            log.Fatal("Creating Service Function Pool Critical Error: ", err)
        }
        sf_pool[sf_name] = sf
    }
    return
}

func init() {
    flag.Parse()

    err := env.LoadConfig(*conf_file_path)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    // Load Service Pool from config file
    service_pool := loadServicePool(env.Config)

    // Load Service Function Pool from configuration file
    sf_pool := loadSfPool(env.Config)

    pep, err := router.NewRouter(service_pool, sf_pool, *log_level)
    if err != nil {
        log.Fatalln(err)
    }

    http.Handle("/", pep)

    err = pep.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
