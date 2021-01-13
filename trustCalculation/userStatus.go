package trustCalculation


type User struct{
	usualGeo []string
	commonUsedService []string
	usualRequest int
	currentRquest int
	authAttempts int
}

func NewUser(_uga []string, _cus []string, _uar int, _car int, _aa int) (User){
	return User{usualGeo: _uga, commonUsedService: _cus, usualRequest: _uar, currentRquest: _car, authAttempts: _aa}
}
