package trustCalculation

/*
This file represents the status of a User. Here are stored several properties of the user, which are necessary for
the calculation of the trust score of the user attributes.
 */

type User struct{
	usualGeo string
	commonUsedService []string
	usualRequest int
	currentRequest int
	authAttempts int
}

func NewUser(_uga string, _cus []string, _uar int, _car int, _aa int) (*User){
	return &User{usualGeo: _uga, commonUsedService: _cus, usualRequest: _uar, currentRequest: _car, authAttempts: _aa}
}

