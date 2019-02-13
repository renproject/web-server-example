package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/renproject/auther/foundation"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Error values.
var (
	ErrCannotInsertToken        = errors.New("cannot insert token")
	ErrCannotSignOrEncryptToken = errors.New("cannot sign or encrypt token")
	ErrCannotParseToken         = errors.New("cannot parse token")
	ErrCannotDecryptToken       = errors.New("cannot decrypt token")
	ErrCannotVerifyClaims       = errors.New("cannot verify claims")
	ErrTokenNotFound            = errors.New("token not found")
)

// A Store interface exposes methods for writing and reading to and from a persistent database.
type Store interface {
	InsertToken(token *foundation.Token) error
	DeleteToken(uuid uuid.UUID) error
	Token(uuid uuid.UUID) (foundation.Token, error)
}

type Tokens interface {
	GenerateToken(userID int64, access foundation.Access) (foundation.Token, error)
	VerifyToken(rawToken string, access foundation.Access) (foundation.Token, error)
	DeactivateToken(token *foundation.Token) error
}

type tokens struct {
	store Store

	secret []byte
	signer jose.Signer
}

func New(store Store, secret []byte) Tokens {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(fmt.Errorf("init signer error = %v", err))
	}
	return &tokens{store, secret, signer}
}

func (tokens *tokens) GenerateToken(userID int64, access foundation.Access) (foundation.Token, error) {
	tokenUUID := uuid.New()
	tokenCreatedAt := time.Now()
	tokenExpiredAt := time.Now().Add(24 * 7 * time.Hour)
	tokenClaims := jwt.Claims{
		ID:       tokenUUID.String(),
		Subject:  fmt.Sprintf("%d", userID),
		IssuedAt: jwt.NewNumericDate(tokenCreatedAt),
		Expiry:   jwt.NewNumericDate(tokenExpiredAt),
	}
	tokenJWT, err := jwt.Signed(tokens.signer).Claims(tokenClaims).CompactSerialize()
	if err != nil {
		return foundation.Token{}, foundation.ErrGeneratingToken{Err: err}
	}

	token := foundation.Token{
		UUID:      tokenUUID,
		CreatedAt: tokenCreatedAt,
		ExpiredAt: tokenExpiredAt,
		Access:    access,
		JWT:       tokenJWT,
		UserID:    userID,
	}
	if err := tokens.store.InsertToken(&token); err != nil {
		return foundation.Token{}, err
	}

	return token, nil
}

func (tokens *tokens) VerifyToken(tokenJWT string, access foundation.Access) (foundation.Token, error) {

	parsedToken, err := jwt.ParseSigned(tokenJWT)
	if err != nil {
		return foundation.Token{}, foundation.ErrParsingToken{Err: err}
	}

	claims := jwt.Claims{}
	if err := parsedToken.Claims(tokens.secret, &claims); err != nil {
		return foundation.Token{}, foundation.ErrParsingToken{Err: err}
	}

	parsedUUID, err := uuid.Parse(claims.ID)
	if err != nil {
		return foundation.Token{}, foundation.ErrParsingToken{Err: err}
	}

	token, err := tokens.store.Token(parsedUUID)
	if err != nil {
		return foundation.Token{}, foundation.ErrVerifyingToken{Err: err}
	}

	if access == token.Access || token.Access == foundation.AccessAll || access == foundation.AccessAny {
		return token, nil
	}
	return foundation.Token{}, foundation.ErrAccessUnauthorized{}
}

func (tokens *tokens) DeactivateToken(token *foundation.Token) error {
	token.ExpiredAt = time.Now()
	if err := tokens.store.DeleteToken(token.UUID); err != nil {
		return err
	}
	return nil
}
