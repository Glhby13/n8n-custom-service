package authservice

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238: HMAC-SHA1 is the TOTP default every authenticator app implements
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	totpPeriod = 30
	totpDigits = 6
	secretLen  = 20
	// secretAlphabet is what Keycloak itself uses for generated OTP secrets: the secret is kept as this raw string and
	// authenticator apps receive its base32 form.
	secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// newOTPSecret returns a fresh raw secret (what Keycloak stores) and its base32 form (what the QR code carries).
func newOTPSecret() (raw, b32 string, err error) {
	var sb strings.Builder
	max := big.NewInt(int64(len(secretAlphabet)))
	for range secretLen {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", "", err
		}
		sb.WriteByte(secretAlphabet[n.Int64()])
	}
	raw = sb.String()
	return raw, strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(raw)), "="), nil
}

func totpAt(key []byte, step int64) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(step)) // #nosec G115 -- step is a positive Unix time quotient
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", v)
}

// validTOTP checks a six digit code against the raw secret with one 30 second step of tolerance either side.
func validTOTP(raw, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	step := now.Unix() / totpPeriod
	ok := 0
	for d := int64(-1); d <= 1; d++ {
		if hmac.Equal([]byte(totpAt([]byte(raw), step+d)), []byte(code)) {
			ok = 1
		}
	}
	return ok == 1
}

// qrDataURI renders the otpauth enrolment URI as a PNG data URI.
func qrDataURI(b32, account, issuer string) (string, error) {
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer+":"+account), url.QueryEscape(b32), url.QueryEscape(issuer), totpDigits, totpPeriod)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
