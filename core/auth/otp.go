package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/renproject/auther/foundation"
)

func VerifyOTP(otp, otpKey string) error {
	computedOTP, err := ComputeOTP(otpKey)
	if err != nil {
		return foundation.ErrVerifyingOTP{err}
	}
	if otp != computedOTP {
		return foundation.ErrOTPIsIncorrect{}
	}
	return nil
}

func ComputeOTP(otpKey string) (string, error) {

	// Compute the 30 s interval as big-endian bytes
	interval := time.Now().Unix() / 30
	intervalBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(intervalBytes, uint64(interval))

	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(otpKey))
	if err != nil {
		return "", foundation.ErrComputingOTP{err}
	}

	// Sign the interval using HMAC-SHA1
	hash := hmac.New(sha1.New, key)
	hash.Write(intervalBytes)
	h := hash.Sum(nil)

	// Use the last nibble (half-byte) to build the header
	var header uint32
	o := (h[19] & 15)
	r := bytes.NewReader(h[o : o+4])
	if err := binary.Read(r, binary.BigEndian, &header); err != nil {
		return "", foundation.ErrComputingOTP{err}
	}

	// Ignore most significant bits (RFC 4226)
	h12 := (int(header) & 0x7fffffff) % 1000000

	return leftPad(strconv.Itoa(int(h12))), nil
}

func leftPad(otp string) string {
	for {
		if len(otp) >= 6 {
			return otp
		}
		otp = "0" + otp
	}
}
