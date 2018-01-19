// Package raw provides a raw implementation of the modular-crypt-wrapped scrypt primitive.
package raw

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// The current recommended time value for interactive logins.
const RecommendedTime uint32 = 4

// The current recommended memory for interactive logins.
const RecommendedMemory uint32 = 32 * 1024

// The current recommended number of threads for interactive logins.
const RecommendedThreads uint8 = 4

// Wrapper for golang.org/x/crypto/argon2 implementing a sensible
// hashing interface.
//
// password should be a UTF-8 plaintext password.
// salt should be a random salt value in binary form.
//
// Time, memory, and threads are parameters to argon2.
//
// Returns an argon2 encoded hash.
func Argon2(password string, salt []byte, time, memory uint32, threads uint8) string {

	passwordb := []byte(password)

	hash := argon2.Key(passwordb, salt, time, memory, threads, 32)

	hstr := base64.RawStdEncoding.EncodeToString(hash)
	sstr := base64.RawStdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, time, threads, sstr, hstr)
}

// Indicates that a password hash or stub is invalid.
var ErrInvalidStub = fmt.Errorf("invalid argon2 password stub")

var ErrInvalidKeyValuePair = fmt.Errorf("invalid argon2 key-value pair")

// Parses an argon2 encoded hash.
//
// The format is as follows:
//
//   $argon2i$v=version$m=memory,t=time,p=threads$salt$hash   // hash
//   $argon2i$v=version$m=memory,t=time,p=threads$salt        // stub
//
func Parse(stub string) (salt, hash []byte, version int, time, memory uint32, threads uint8, err error) {
	if len(stub) < 26 || !strings.HasPrefix(stub, "$argon2i$") {
		err = ErrInvalidStub
		return
	}

	// $argon2i$  v=version$m=memory,t=time,p=threads$salt-base64$hash-base64
	parts := strings.Split(stub[9:], "$")

	if len(parts) < 3 {
		err = ErrInvalidStub
		return
	}

	versionParams, err := parseKeyValuePair(parts[0])

	if err != nil {
		return
	}

	if len(versionParams) != 1 {
		err = fmt.Errorf("expected %d version parameters, got %d", 1, len(versionParams))
		return
	}

	val, ok := versionParams["v"]

	if !ok {
		err = errors.New("version (v) parameter is missing")
		return
	}

	version = int(val)

	hashParams, err := parseKeyValuePair(parts[1])

	if err != nil {
		return
	}

	if len(hashParams) != 3 {
		err = fmt.Errorf("expected %d hash parameters, got %d", 3, len(hashParams))
		return
	}

	val, ok = hashParams["m"]

	if !ok {
		err = errors.New("memory (m) parameter is missing")
		return
	}

	memory = uint32(val)

	val, ok = hashParams["t"]

	if !ok {
		err = errors.New("time (t) parameter is missing")
		return
	}

	time = uint32(val)
	val, ok = hashParams["p"]

	if !ok {
		err = errors.New("threads (p) parameter is missing")
		return
	}

	threads = uint8(val)

	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}

	if len(parts) >= 4 {
		hash, err = base64.RawStdEncoding.DecodeString(parts[3])
	}

	return
}

func parseKeyValuePair(pairs string) (result map[string]uint64, err error) {

	result = map[string]uint64{}

	parameterParts := strings.Split(pairs, ",")

	for _, parameter := range parameterParts {
		parts := strings.Split(parameter, "=")

		if len(parts) != 2 {
			err = ErrInvalidKeyValuePair
			return
		}

		parsedi, err := strconv.ParseUint(parts[1], 10, 32)

		if err != nil {
			return result, err
		}

		result[parts[0]] = parsedi
	}

	return result, nil
}
