package hash

import "fmt"
import "crypto/rand"
import "github.com/hlandau/passlib/hash/raw"

// An implementation of Scheme performing sha256-crypt.
var SHA256Crypter Scheme

// An implementation of Scheme performing sha512-crypt.
var SHA512Crypter Scheme

func init() {
	SHA256Crypter = &sha2Crypter{false, raw.SHA2CryptRecommendedRounds}
	SHA512Crypter = &sha2Crypter{true, raw.SHA2CryptRecommendedRounds}
}

type sha2Crypter struct {
	sha512 bool
	rounds int
}

// Changes the default rounds for the crypter. Be warned that this
// is a global setting. The default default value is SHA2CryptRecommendedRounds.
func (c *sha2Crypter) SetRounds(rounds int) error {
	if rounds < raw.SHA2CryptMinimumRounds || rounds > raw.SHA2CryptMaximumRounds {
		return raw.ErrInvalidRounds
	}

	c.rounds = rounds
	return nil
}

func (c *sha2Crypter) SupportsStub(stub string) bool {
	if len(stub) < 3 || stub[0] != '$' || stub[2] != '$' {
		return false
	}
	return (stub[1] == '5' && !c.sha512) || (stub[1] == '6' && c.sha512)
}

func (c *sha2Crypter) Hash(password, stub string) (string, error) {
	_, newHash, _, _, err := c.hash(password, stub)
	return newHash, err
}

func (c *sha2Crypter) Verify(password, hash string) (newHash string, err error) {
	_, newHash, salt, rounds, err := c.hash(password, hash)
	if err == nil && hash != newHash {
		err = ErrIncorrectPassword
	}

	newHash = ""
	if err == nil {
		newHash = c.getUpgradeHash(password, salt, rounds)
	}

	return
}

func (c *sha2Crypter) NeedsUpdate(stub string) bool {
	_, salt, _, rounds, err := raw.ParseSHA256Crypt(stub)
	if err != nil {
		return false // ...
	}

	return c.needsUpdate(salt, rounds)
}

func (c *sha2Crypter) needsUpdate(salt string, rounds int) bool {
	return rounds < c.rounds || len(salt) < 16
}

func (c *sha2Crypter) getUpgradeHash(password, salt string, rounds int) string {
	if !c.needsUpdate(salt, rounds) {
		// no need to upgrade
		return ""
	}

	newStub, err := c.MakeStub()
	if err != nil {
		return ""
	}

	newHash, err := c.Hash(password, newStub)
	if err != nil {
		return ""
	}

	return newHash
}

func (c *sha2Crypter) hash(password, stub string) (oldHash, newHash, salt string, rounds int, err error) {
	isSHA512, salt, oldHash, rounds, err := raw.ParseSHA256Crypt(stub)
	if err != nil {
		return "", "", "", 0, err
	}

	if isSHA512 != c.sha512 {
		return "", "", "", 0, raw.ErrInvalidStub
	}

	if c.sha512 {
		return oldHash, raw.SHA512Crypt(password, salt, rounds), salt, rounds, nil
	}

	return oldHash, raw.SHA256Crypt(password, salt, rounds), salt, rounds, nil
}

func (c *sha2Crypter) MakeStub() (string, error) {
	ch := "5"
	if c.sha512 {
		ch = "6"
	}

	buf := make([]byte, 12)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	salt := raw.EncodeBase64(buf)[0:16]

	if c.rounds == raw.SHA2CryptDefaultRounds {
		return fmt.Sprintf("$%s$%s", ch, salt), nil
	}

	return fmt.Sprintf("$%s$rounds=%d$%s", ch, c.rounds, salt), nil
}

var ErrIncorrectPassword = fmt.Errorf("incorrect password")

// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
