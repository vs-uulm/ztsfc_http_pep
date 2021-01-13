package trustCalculation

/*
In this file the threshold values for the three provided services, the trust-increase for user-attribtues, the
trust-increase for device attribtues, user-information and device information of managed devices is stored
 */

// Trust-increase, when a DPI is used
var dpiTrustIncrease = 6

// Map, where threshold values for the devices are stored
var thresholdValues map[string]int

// Map, where the trust-increase of user attributes is provided, when these attributes are fulfilled
var trustIncreaseUserAttr map[string]int

// Map, where the trust-increase of device attributes is provided, when these attributes are fulfilled
var trustIncreaseDeviceAttr map[string]int

var userDatabase map[string]User

// Map, where the current status of managed devices is stored
var deviceDatabase map[string]map[string]bool


// In this method, the specified data sources are filled with content
func InitDataSources()  {
	thresholdValues["service1"] = 11
	thresholdValues["service2"] = 14
	thresholdValues["service3"] = 17

	trustIncreaseUserAttr["UGA"] = 1 	// Usual geographic area
	trustIncreaseUserAttr["CUS"] = 2 	// Commonly used services
	trustIncreaseUserAttr["UAR"] = 2 	// Usual amount of requests
	trustIncreaseUserAttr["AA"] = 3 	// Authentication attempts
	trustIncreaseUserAttr["CRT"] = 2 	// Authentication with a client-certificate
	trustIncreaseUserAttr["CRT_PW"] = 3	// Authentication with a client-certificate and a password

	trustIncreaseDeviceAttr["LPL"] = 3	// Latest patch level
	trustIncreaseDeviceAttr["NAVS"] = 2	// No alerts of virus scanner
	trustIncreaseDeviceAttr["RI"] = 1	// Re-installation

	var device1 map[string]bool
	deviceDatabase["device1"] = device1
	device1["LPL"] = true
	device1["NAVS"] = true
	device1["RI"] = false
	var device2 map[string]bool
	deviceDatabase["device2"] = device1
	device2["LPL"] = false
	device2["NAVS"] = true
	device2["RI"] = false

	user := NewUser([]string{"DE","FR"},[]string{"service1"},1000,300,1)
	userDatabase["alex"] = user




}