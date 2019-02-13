package resolver

import (
	"github.com/renproject/auther/core/auth"
	"github.com/renproject/auther/core/token"
	"github.com/renproject/auther/foundation"
)

type Resolver struct {
	authenticator auth.Authenticator
	tokens        token.Tokens
}

func (r *Resolver) Login(username, password, otp string) (foundation.Account, foundation.Token, error) {
	account, err := r.authenticator.VerifyUsernamePasswordOTP(username, password, otp)
	if err != nil {
		return foundation.Account{}, foundation.Token{}, err
	}
	token, err := r.tokens.GenerateToken(account.UserID, foundation.AccessAll)
	if err != nil {
		return foundation.Account{}, foundation.Token{}, err
	}
	return account, token, nil
}
