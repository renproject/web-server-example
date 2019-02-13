package auth

import (
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	AccountByUsername(userame string) (foundation.Account, error)
}

type Authenticator interface {
	VerifyUsernamePasswordOTP(userame, password, otp string) (foundation.Account, error)
}

type authenticator struct {
	store Store
}

func NewAuthenticator(store Store) Authenticator {
	return &authenticator{store}
}

func (authenticator *authenticator) VerifyUsernamePasswordOTP(userame, password, otp string) (foundation.Account, error) {

	account, err := authenticator.store.AccountByUsername(userame)
	if err != nil {
		// Set the password to something invalid so that verification is
		// guaranteed to fail
		password = ""
	}

	// Always compare the password to protect against timing attacks
	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		return foundation.Account{}, foundation.ErrUsernameOrPasswordIsIncorrect{}
	}
	if account.OTPKey != "" {
		if err := VerifyOTP(otp, account.OTPKey); err != nil {
			return foundation.Account{}, err
		}
	}

	return account, nil
}
