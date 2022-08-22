package init

import (
    "fmt"
    "crypto/x509"

    "github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
    gct "github.com/leobrada/golang_convenience_tools"
)

func initPip() error {
    fields := ""
    var err error

    if config.Config.Pip.TargetAddr == "" {
        fields += "target_addr"
    }

    // TODO: add device endpoint? or is it ok if its left empty?
    // TODO: add user endpoint? or is it ok if its left empty?
    // TODO: add system endpoint? or it it ok if its left empty?

    if config.Config.Pip.CertsPepAcceptsWhenShownByPip == nil {
        fields += "certs_pep_accepts_when_shown_by_pip"
    }

    if config.Config.Pip.CertShownByPepToPip == "" {
        fields += "cert_shown_by_pep_to_pip"
    }

    if config.Config.Pip.PrivkeyForCertShownByPepToPip == "" {
        fields += "privkey_for_certs_shown_by_pep_to_pip"
    }

    // Read CA certs and PDP certificate used for the PIP connection
    config.Config.Pip.CaCertPoolPepAcceptsFromPip = x509.NewCertPool()
    for _, acceptedPipCert := range config.Config.Pip.CertsPepAcceptsWhenShownByPip {
        if err = gct.LoadCACertificate(acceptedPipCert, config.Config.Pip.CaCertPoolPepAcceptsFromPip); err != nil {
            return fmt.Errorf("initPipParams(): error loading certificates PEP accepts from PIP: %w", err)
        }
    }

    config.Config.Pip.X509KeyPairShownByPepToPip, err = gct.LoadX509KeyPair(config.Config.Pip.CertShownByPepToPip,
        config.Config.Pip.PrivkeyForCertShownByPepToPip)
    if err != nil {
        return fmt.Errorf("initPipParams(): error loading certificates PEP shows to PIP: %w", err)
    }

    config.Config.Pip.PipClient = gct.NewHTTPSClient(config.Config.Pip.CaCertPoolPepAcceptsFromPip, config.Config.Pip.X509KeyPairShownByPepToPip)

    return err
}
