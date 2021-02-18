package main

import (
    "log"
    "crypto/x509"
    "net/http"
    "flag"
    "os"

    env "local.com/leobrada/ztsfc_http_pep/env"
    router "local.com/leobrada/ztsfc_http_pep/router"
    logr "local.com/leobrada/ztsfc_http_pep/logwriter"
    sf_init "local.com/leobrada/ztsfc_http_pep/init"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
    log_level = flag.Int("l", 0, "Log level")
)


func init() {
    flag.Parse()

    // Loading all config parameter from config file defined in "conf_file_path"
    err := env.LoadConfig(*conf_file_path)
    if err != nil {
        log.Fatal(err)
    }

    // Create Logwriter
    logChannel := make(chan []byte, 128)
    logr.Log_writer = logr.NewLogWriter(*log_level, "./access.log", logChannel, 5)
	go logr.Log_writer.Work()

    // Loading all service related information into env.Config
    err = sf_init.LoadServicePool(env.Config)
    if err != nil {
        os.Exit(1)
    }


    // Loading all sf related information into env.Config
    err = sf_init.LoadSfPool(env.Config)
    if err != nil {
        os.Exit(1)
    }

    // Create Certificate Pools for the CA certificates used by the PEP
    env.Config.CA_cert_pool_pep_accepts_from_ext = x509.NewCertPool()
    env.Config.CA_cert_pool_pep_accepts_from_int = x509.NewCertPool()

    // Load all CA certificates
    err = sf_init.InitAllCACertificates()
    if err != nil {
       os.Exit(1)
    }

}

func main() {

    // Create new PEP router
    pep, err := router.NewRouter()
    if err != nil {
        log.Fatalln(err)
    }

    http.Handle("/", pep)

    err = pep.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
