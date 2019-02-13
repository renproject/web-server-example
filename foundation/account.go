package foundation

import "time"

type Account struct {
	ID           int64     `db:"id"`
	CreatedAt    time.Time `db:"created_at"`
	ExpiredAt    time.Time `db:"expired_at"`
	Username     string    `db:"username"`
	PasswordHash string    `db:"password"`
	OTPKey       string    `db:"otp_key"`
	UserID       int64     `db:"u_id"`
}
