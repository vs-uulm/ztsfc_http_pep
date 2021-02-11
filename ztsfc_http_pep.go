package main

import (
    "log"
    "net/http"
    "net/url"
    "flag"
    "crypto/tls"

    env "local.com/leobrada/ztsfc_http_pep/env"
    router "local.com/leobrada/ztsfc_http_pep/router"
//    sf_info "local.com/leobrada/ztsfc_http_pep/sf_info"
    logr "local.com/leobrada/ztsfc_http_pep/logwriter"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
    log_level = flag.Int("l", 0, "Log level")
)

func loadServicePool(config env.Config_t) {
    var err error
    for service_name, service_config := range(env.Config.Service_pool) {
        // Preload X509KeyPairs shown by pep to client
        env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_client, err = tls.LoadX509KeyPair(
            service_config.Cert_shown_by_pep_to_clients_matching_sni,
            service_config.Privkey_for_cert_shown_by_pep_to_client)
        if err != nil {
            log.Fatal("Loading X509KeyPair Critical Error", err)
        }
        // Preload X509KeyPairs shown by pep to service
        env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_service, err = tls.LoadX509KeyPair(
            service_config.Cert_shown_by_pep_to_service,
            service_config.Privkey_for_cert_shown_by_pep_to_service)
        if err != nil {
            log.Fatal("Loading X509KeyPair Critical Error", err)
        }
        // Preparse Service URL
        env.Config.Service_pool[service_name].Target_service_url, err = url.Parse(service_config.Target_service_addr)
        if err != nil {
            log.Fatal("Parsing Target Service URL Critical Error", err)
        }
    }
}

func loadSfPool(config env.Config_t) {
    var err error
    for sf_name, sf_config := range(env.Config.Sf_pool) {
        // preload X509KeyPairs shown by pep to sf
        env.Config.Sf_pool[sf_name].X509KeyPair_shown_by_pep_to_sf, err = tls.LoadX509KeyPair(
            sf_config.Cert_shown_by_pep_to_sf,
            sf_config.Privkey_for_cert_shown_by_pep_to_sf)
        if err != nil {
            log.Fatal("Loading X509KeyPair Critical Error", err)
        }
        // Preparse SF URL
        env.Config.Sf_pool[sf_name].Target_sf_url, err = url.Parse(sf_config.Target_sf_addr)
        if err != nil {
            log.Fatal("Parsing Target SF URL Critical Error", err)
        }
    }
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
    loadServicePool(env.Config)

    // Load Service Function Pool from configuration file
    loadSfPool(env.Config)

    // Create Logwriter
    logChannel := make(chan []byte, 128)
    log_writer := logr.NewLogWriter(*log_level, "./access.log", logChannel, 5)

    // Create new PEP router
    pep, err := router.NewRouter(log_writer)
    if err != nil {
        log.Fatalln(err)
    }

    http.Handle("/", pep)

    err = pep.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
