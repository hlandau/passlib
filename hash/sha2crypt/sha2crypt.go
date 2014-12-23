package sha2crypt

import "fmt"
import "crypto/rand"
import "github.com/hlandau/passlib/hash/sha2crypt/raw"
import "github.com/hlandau/passlib/abstract"

// An implementation of Scheme performing sha256-crypt.
//
// The number of rounds is raw.RecommendedRounds.
var Crypter256 abstract.Scheme

// An implementation of Scheme performing sha512-crypt.
//
// The number of rounds is raw.RecommendedRounds.
var Crypter512 abstract.Scheme

func init() {
	Crypter256 = NewCrypter256(raw.RecommendedRounds)
	Crypter512 = NewCrypter512(raw.RecommendedRounds)
}

// Returns a Scheme implementing sha256-crypt using the number of rounds
// specified.
func NewCrypter256(rounds int) abstract.Scheme {
  return &sha2Crypter{false, rounds}
}

// Returns a Scheme implementing sha512-crypt using the number of rounds
// specified.
func NewCrypter512(rounds int) abstract.Scheme {
  return &sha2Crypter{true, rounds}
}

type sha2Crypter struct {
	sha512 bool
	rounds int
}

// Changes the default rounds for the crypter. Be warned that this
// is a global setting. The default default value is RecommendedRounds.
func (c *sha2Crypter) SetRounds(rounds int) error {
	if rounds < raw.MinimumRounds || rounds > raw.MaximumRounds {
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
		err = abstract.ErrInvalidPassword
	}

	newHash = ""
	if err == nil {
		newHash = c.getUpgradeHash(password, salt, rounds)
	}

	return
}

func (c *sha2Crypter) NeedsUpdate(stub string) bool {
	_, salt, _, rounds, err := raw.Parse(stub)
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

var errInvalidStub = fmt.Errorf("invalid sha2 password stub")

func (c *sha2Crypter) hash(password, stub string) (oldHash, newHash, salt string, rounds int, err error) {
	isSHA512, salt, oldHash, rounds, err := raw.Parse(stub)
	if err != nil {
		return "", "", "", 0, err
	}

	if isSHA512 != c.sha512 {
		return "", "", "", 0, errInvalidStub
	}

	if c.sha512 {
		return oldHash, raw.Crypt512(password, salt, rounds), salt, rounds, nil
	}

	return oldHash, raw.Crypt256(password, salt, rounds), salt, rounds, nil
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

	if c.rounds == raw.DefaultRounds {
		return fmt.Sprintf("$%s$%s", ch, salt), nil
	}

	return fmt.Sprintf("$%s$rounds=%d$%s", ch, c.rounds, salt), nil
}

// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
