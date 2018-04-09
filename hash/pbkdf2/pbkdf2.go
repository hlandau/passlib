package pbkdf2

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"gopkg.in/hlandau/passlib.v1/abstract"
	"gopkg.in/hlandau/passlib.v1/hash/pbkdf2/raw"
	"hash"
	"strings"
)

// An implementation of Scheme implementing pkbdf2 variations.
//
// Uses RecommendedCost.
var Crypter1 abstract.Scheme
var Crypter256 abstract.Scheme
var Crypter512 abstract.Scheme

const SaltLength = 16

func init() {
	Crypter1 = New("$pbkdf2$", sha1.New, 131000)
	Crypter256 = New("$pbkdf2-sha256$", sha256.New, 29000)
	Crypter512 = New("$pbkdf2-sha512$", sha512.New, 25000)
}

type scheme struct {
	Ident    string
	HashFunc func() hash.Hash
	Rounds   int
}

func New(ident string, hf func() hash.Hash, rounds int) abstract.Scheme {
	return &scheme{
		Ident:    ident,
		HashFunc: hf,
		Rounds:   rounds,
	}
}

func (s *scheme) Hash(password string) (string, error) {
	salt := make([]byte, SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hash := raw.Hash([]byte(password), salt, s.Rounds, s.HashFunc)

	newHash := fmt.Sprintf("%s%d$%s$%s", s.Ident, s.Rounds, raw.Base64Encode(salt), hash)
	return newHash, nil
}

func (s *scheme) Verify(password, stub string) (err error) {
	_, rounds, salt, oldHash, err := raw.Parse(stub)
	if err != nil {
		return
	}

	newHash := raw.Hash([]byte(password), salt, rounds, s.HashFunc)

	if len(newHash) == 0 || !abstract.SecureCompare(oldHash, newHash) {
		err = abstract.ErrInvalidPassword
	}

	return
}

func (s *scheme) SupportsStub(stub string) bool {
	return strings.HasPrefix(stub, s.Ident)
}

func (s *scheme) NeedsUpdate(stub string) bool {
	_, rounds, salt, _, err := raw.Parse(stub)
	return err == raw.ErrInvalidRounds || rounds < s.Rounds || len(salt) < SaltLength
}
