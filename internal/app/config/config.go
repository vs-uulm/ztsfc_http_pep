// Package config reads the config file and parses it to go data structures.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config contains all input from the config file and is is globally accessible
var (
	Config ConfigT
)

type sysLoggerT struct {
	LogLevel        string `yaml:"system_logger_logging_level"`
	LogFilePath     string `yaml:"system_logger_destination"`
	IfTextFormatter string `yaml:"system_logger_format"`
}

type BlocklistsT struct {
	PathToBotnetList string `yaml:"path_to_botnet_list"`
	BotnetList       map[string]struct{}
	WaitBotnetList   sync.WaitGroup
}

// The struct PepT is for parsing the section 'pep' of the config file.
type PepT struct {
	ListenAddr                        string   `yaml:"listen_addr"`
	CertsPepAcceptsWhenShownByClients []string `yaml:"certs_pep_accepts_when_shown_by_clients"`
	DefaultPoolSize                   int      `yaml:"default_pool_size"`
}

type BasicAuthT struct {
	Passwd  PasswdT  `yaml:"passwd"`
	Session SessionT `yaml:"session"`
	RPID    string   `yaml:"rpid"`
}

type PasswdT struct {
	PathToPasswd         string              `yaml:"path_to_passwd"`
	PasswdListByUsername map[string]*ShadowT // Key is username
	PasswdListByID       map[string]*ShadowT // Key is ID (string)
	WaitPasswdList       sync.WaitGroup
}

type ShadowT struct {
	User   string
	ID     []byte
	Salt   string
	Digest string
}

// ShadowT implements the WebAuthn User interface:
func (user *ShadowT) WebAuthnID() []byte {
	return user.ID
}

func (user *ShadowT) WebAuthnName() string {
	return user.User
}

func (user *ShadowT) WebAuthnDisplayName() string {
	return user.User
}

func (user *ShadowT) WebAuthnIcon() string {
	return ""
}

func (user *ShadowT) WebAuthnCredentials() []webauthn.Credential {
	// Read passkey file
	data, err := ioutil.ReadFile("/passkeys/" + user.User + ".passkey")
	if err != nil {
		log.Fatalf("Failed to read file: %s", err)
	}

	// Unmarshal JSON data
	var credentials protocol.CredentialCreationResponse
	err = json.Unmarshal(data, &credentials)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON data: %s", err)
	}
	parsedCredentials, err := credentials.Parse()
	if err != nil {
		log.Fatalf("Failed to parse credentials: %s", err)
	}
	finalCredentials, err := webauthn.MakeNewCredential(parsedCredentials)
	if err != nil {
		log.Fatalf("Failed to make new credentials: %s", err)
	}
	finalCredentialList := make([]webauthn.Credential, 0)
	finalCredentialList = append(finalCredentialList, *finalCredentials)

	return finalCredentialList
	//return user.credentials
}

func (user *ShadowT) PasskeyExists() bool {
	_, err := os.Stat("/passkeys/" + user.User + ".passkey")
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

//type SessionT struct {
//	Path_to_jwt_pub_key     string `yaml:"path_to_jwt_pub_key"`
//	Path_to_jwt_signing_key string `yaml:"path_to_jwt_signing_key"`
//	JwtPubKey               *rsa.PublicKey
//	MySigningKey            *rsa.PrivateKey
//}

type SessionT struct {
	PathToJwtSigningKey string `yaml:"path_to_jwt_signing_key"`
	JwtSigningKey       string
}

// The struct PdpT is for parsing the section 'pdp' of the config file.
type PdpT struct {
	TargetPdpAddr                 string `yaml:"target_pdp_addr"`
	CertShownByPepToPdp           string `yaml:"cert_shown_by_pep_to_pdp"`
	PrivkeyForCertShownByPepToPdp string `yaml:"privkey_for_cert_shown_by_pep_to_pdp"`
	CertPepAcceptsShownByPdp      string `yaml:"cert_pep_accepts_shown_by_pdp"`
	PdpClientPoolSize             int    `yaml:"pdp_client_pool_size"`
	X509KeyPairShownByPepToPdp    tls.Certificate
}

type PipT struct {
	TargetAddr                       string `yaml:"target_addr"`
	PushUserAttributesUpdateEndpoint string `yaml:"push_user_attribute_update_endpoint"`
	UserEndpoint                     string `yaml:"user_endpoint"`

	CertsPepAcceptsWhenShownByPip []string `yaml:"certs_pep_accepts_when_shown_by_pip"`
	CertShownByPepToPip           string   `yaml:"cert_shown_by_pep_to_pip"`
	PrivkeyForCertShownByPepToPip string   `yaml:"privkey_for_cert_shown_by_pep_to_pip"`

	CaCertPoolPepAcceptsFromPip *x509.CertPool
	X509KeyPairShownByPepToPip  tls.Certificate

	PipClient *http.Client
}

// The struct SfplT is for parsing the section 'sfp_logic' of the config file.
type SfplT struct {
	TargetSfplAddr                 string `yaml:"target_sfpl_addr"`
	CertShownByPepToSfpl           string `yaml:"cert_shown_by_pep_to_sfpl"`
	PrivkeyForCertShownByPepToSfpl string `yaml:"privkey_for_cert_shown_by_pep_to_sfpl"`
	CertPepAcceptsShownBySfpl      string `yaml:"cert_pep_accepts_shown_by_sfpl"`
	SfplClientPoolSize             int    `yaml:"sfpl_client_pool_size"`
	X509KeyPairShownByPepToSfpl    tls.Certificate
}

// The struct ServiceT is for parsing one service from section 'service_pool'
// of the config file.
type ServiceT struct {
	Sni                                string `yaml:"sni"`
	TargetServiceAddr                  string `yaml:"target_service_addr"`
	CertShownByPepToClientsMatchingSni string `yaml:"cert_shown_by_pep_to_clients_matching_sni"`
	PrivkeyForCertShownByPepToClient   string `yaml:"privkey_for_cert_shown_by_pep_to_client"`
	CertShownByPepToService            string `yaml:"cert_shown_by_pep_to_service"`
	PrivkeyForCertShownByPepToService  string `yaml:"privkey_for_cert_shown_by_pep_to_service"`
	CertPepAcceptsWhenShownByService   string `yaml:"cert_pep_accepts_when_shown_by_service"`
	X509KeyPairShownByPepToClient      tls.Certificate
	X509KeyPairShownByPepToService     tls.Certificate
	TargetServiceUrl                   *url.URL
}

// The struct ServFunctionT is for parsing one service function from section
// 'sf_pool' of the config file.
type ServFunctionT struct {
	TargetSfAddr                 string `yaml:"target_sf_addr"`
	CertShownByPepToSf           string `yaml:"cert_shown_by_pep_to_sf"`
	PrivkeyForCertShownByPepToSf string `yaml:"privkey_for_cert_shown_by_pep_to_sf"`
	CertPepAcceptsShownBySf      string `yaml:"cert_pep_accepts_shown_by_sf"`
	X509KeyPairShownByPepToSf    tls.Certificate
	TargetSfUrl                  *url.URL
}

// ConfigT struct is for parsing the basic structure of the config file
type ConfigT struct {
	SysLogger  sysLoggerT  `yaml:"system_logger"`
	Blocklists BlocklistsT `yaml:"blocklists"`
	Pep        PepT        `yaml:"pep"`
	BasicAuth  BasicAuthT  `yaml:"basic_auth"`
	Pdp        PdpT        `yaml:"pdp"`
	Pip        PipT        `yaml:"pip"`
	SfpLogic   SfplT       `yaml:"sfp_logic"`
	// TODO: Use Structs of ServiceT and ServFunctionT instead of pointers to the structs?
	ServicePool                 map[string]*ServiceT      `yaml:"service_pool"`
	SfPool                      map[string]*ServFunctionT `yaml:"sf_pool"`
	CAcertPoolPepAcceptsFromExt *x509.CertPool
	CAcertPoolPepAcceptsFromInt *x509.CertPool
	ServiceSniMap               map[string]*ServiceT
}

// LoadConfig() parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string) error {
	// If the config file path was not provided
	if configPath == "" {
		return errors.New("no configuration file is provided")
	}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to open the YAML configuration file '%s': %w", configPath, err)
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Decode configuration from the YAML config file
	err = d.Decode(&Config)
	if err != nil {
		return fmt.Errorf("unable to decode the YAML configuration file '%s': %w", configPath, err)
	}
	return nil
}
