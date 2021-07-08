package env

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Pep_t struct {
	Listen_addr                             string   `yaml:"listen_addr"`
	Certs_pep_accepts_when_shown_by_clients []string `yaml:"certs_pep_accepts_when_shown_by_clients"`
}

type LDAP_t struct {
	Base         string   `yaml:"base"`
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	UseSSL       bool     `yaml:"use_ssl"`
	BindDN       string   `yaml:"bind_dn"`
	BindPassword string   `yaml:"bind_password"`
	UserFilter   string   `yaml:"user_filter"`
	GroupFilter  string   `yaml:"group_filter"`
	Attributes   []string `yaml:"attributes"`
}

type Pdp_t struct {
	Target_pdp_addr                      string `yaml:"target_pdp_addr"`
	Cert_shown_by_pep_to_pdp             string `yaml:"cert_shown_by_pep_to_pdp"`
	Privkey_for_cert_shown_by_pep_to_pdp string `yaml:"privkey_for_cert_shown_by_pep_to_pdp"`
	Cert_pep_accepts_shown_by_pdp        string `yaml:"cert_pep_accepts_shown_by_pdp"`
	Pdp_client_pool_size                 int    `yaml:"pdp_client_pool_size"`
	X509KeyPair_shown_by_pep_to_pdp      tls.Certificate
}

type Sfpl_t struct {
	Target_sfpl_addr                      string `yaml:"target_sfpl_addr"`
	Cert_shown_by_pep_to_sfpl             string `yaml:"cert_shown_by_pep_to_sfpl"`
	Privkey_for_cert_shown_by_pep_to_sfpl string `yaml:"privkey_for_cert_shown_by_pep_to_sfpl"`
	Cert_pep_accepts_shown_by_sfpl        string `yaml:"cert_pep_accepts_shown_by_sfpl"`
	Sfpl_client_pool_size                 int    `yaml:"sfpl_client_pool_size"`
	X509KeyPair_shown_by_pep_to_sfpl      tls.Certificate
}

type Service_t struct {
	Sni                                       string `yaml:"sni"`
	Target_service_addr                       string `yaml:"target_service_addr"`
	Cert_shown_by_pep_to_clients_matching_sni string `yaml:"cert_shown_by_pep_to_clients_matching_sni"`
	Privkey_for_cert_shown_by_pep_to_client   string `yaml:"privkey_for_cert_shown_by_pep_to_client"`
	Cert_shown_by_pep_to_service              string `yaml:"cert_shown_by_pep_to_service"`
	Privkey_for_cert_shown_by_pep_to_service  string `yaml:"privkey_for_cert_shown_by_pep_to_service"`
	Cert_pep_accepts_when_shown_by_service    string `yaml:"cert_pep_accepts_when_shown_by_service"`
	X509KeyPair_shown_by_pep_to_client        tls.Certificate
	X509KeyPair_shown_by_pep_to_service       tls.Certificate
	Target_service_url                        *url.URL
}

type ServFunction_t struct {
	Target_sf_addr                      string `yaml:"target_sf_addr"`
	Cert_shown_by_pep_to_sf             string `yaml:"cert_shown_by_pep_to_sf"`
	Privkey_for_cert_shown_by_pep_to_sf string `yaml:"privkey_for_cert_shown_by_pep_to_sf"`
	Cert_pep_accepts_shown_by_sf        string `yaml:"cert_pep_accepts_shown_by_sf"`
	X509KeyPair_shown_by_pep_to_sf      tls.Certificate
	Target_sf_url                       *url.URL
}

type Config_t struct {
	Pep                               Pep_t                      `yaml:"pep"`
	Ldap                              LDAP_t                     `yaml:"ldap"`
	Pdp                               Pdp_t                      `yaml:"pdp"`
	Sfp_logic                         Sfpl_t                     `yaml:"sfp_logic"`
	Service_pool                      map[string]*Service_t      `yaml:"service_pool"`
	Sf_pool                           map[string]*ServFunction_t `yaml:"sf_pool"`
	CA_cert_pool_pep_accepts_from_ext *x509.CertPool
	CA_cert_pool_pep_accepts_from_int *x509.CertPool
	Service_SNI_map                   map[string]*Service_t
}

var Config Config_t

// Parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string, sysLogger *logrus.Entry) (err error) {
	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		sysLogger.Fatalf("Open configuration file error: %v", err)
	} else {
		sysLogger.Debugf("Configuration file %s exists and is readable", configPath)
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	err = d.Decode(&Config)
	if err != nil {
		sysLogger.Fatalf("Configuration yaml-->go decoding error: %v", err)
	} else {
		sysLogger.Debugf("Configuration has been successfully decoded")
	}

	return
}
