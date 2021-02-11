package env

import (
	"gopkg.in/yaml.v2"
	"os"
    "crypto/tls"
    "net/url"
)

type Pep_t struct {
	Listen_addr                             string   `yaml:"listen_addr"`
	Certs_pep_accepts_when_shown_by_clients []string `yaml:"certs_pep_accepts_when_shown_by_clients"`
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
	Pep          Pep_t                     `yaml:"pep"`
	Service_pool map[string]*Service_t      `yaml:"service_pool"`
	Sf_pool      map[string]*ServFunction_t `yaml:"sf_pool"`
}

var Config Config_t

// Parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string) (err error) {
	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	err = d.Decode(&Config)
	return
}
