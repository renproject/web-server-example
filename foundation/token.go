package foundation

import (
	"time"

	"github.com/google/uuid"
)

type Access string

var (
	AccessReset    = Access("reset")
	AccessActivate = Access("activate")
	AccessAll      = Access("all")
	AccessAny      = Access("any")
)

type Token struct {
	ID        int64
	UUID      uuid.UUID
	CreatedAt time.Time
	ExpiredAt time.Time
	Access    Access
	JWT       string
	UserID    int64
}
