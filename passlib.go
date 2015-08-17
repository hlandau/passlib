// Package passlib provides a simple password hashing and verification
// interface abstracting multiple password hashing schemes.
//
// Most people need concern themselves only with the functions Hash
// and Verify, which uses the default context and sensible defaults.
package passlib

import "github.com/hlandau/passlib/abstract"
import "github.com/hlandau/passlib/hash/scrypt"
import "github.com/hlandau/passlib/hash/sha2crypt"
import "github.com/hlandau/degoutils/metric"

var cHashCalls = metric.NewCounter("passlib.ctx.hashCalls")
var cVerifyCalls = metric.NewCounter("passlib.ctx.verifyCalls")
var cSuccessfulVerifyCalls = metric.NewCounter("passlib.ctx.successfulVerifyCalls")
var cFailedVerifyCalls = metric.NewCounter("passlib.ctx.failedVerifyCalls")
var cSuccessfulVerifyCallsWithUpgrade = metric.NewCounter("passlib.ctx.successfulVerifyCallsWithUpgrade")

// The default schemes, most preferred first. The first scheme will be used to
// hash passwords, and any of the schemes may be used to verify existing
// passwords. The contents of this value may change with subsequent releases.
var DefaultSchemes = []abstract.Scheme{
	scrypt.SHA256Crypter,
	sha2crypt.Crypter256,
	sha2crypt.Crypter512}

type Context struct {
	// Slice of schemes to use, most preferred first.
	//
	// If left uninitialized, a sensible default set of schemes will be used.
	//
	// An upgrade hash (see the newHash return value of the Verify method of the
	// abstract.Scheme interface) will be issued whenever a password is validated
	// using a scheme which is not the first scheme in this slice.
	Schemes []abstract.Scheme
}

func (ctx *Context) init() {
	if len(ctx.Schemes) == 0 {
		ctx.Schemes = DefaultSchemes
	}
}

// Randomly generates a new password stub for the preferred password hashing
// scheme of the context.
func (ctx *Context) MakeStub() (string, error) {
	ctx.init()

	return ctx.Schemes[0].MakeStub()
}

// Hashes a UTF-8 plaintext password using the context and produces a password hash.
//
// If stub is "", one is generated automaticaly for the preferred password hashing
// scheme; you should specify stub as "" in almost all cases.
//
// The provided or randomly generated stub is used to deterministically hash
// the password. The returned hash is in modular crypt format.
//
// If the context has not been specifically configured, a sensible default policy
// is used. See the fields of Context.
func (ctx *Context) Hash(password, stub string) (hash string, err error) {
	ctx.init()
	cHashCalls.Add(1)

	if stub == "" {
		stub, err = ctx.MakeStub()
		if err != nil {
			return
		}
	}

	for _, scheme := range ctx.Schemes {
		if scheme.SupportsStub(stub) {
			return scheme.Hash(password, stub)
		}
	}

	err = abstract.ErrUnsupportedScheme
	return
}

// Verifies a UTF-8 plaintext password using a previously derived password hash
// and the default context. Returns nil err only if the password is valid.
//
// If the hash is determined to be deprecated based on the context policy, and
// the password is valid, the password is hashed using the preferred password
// hashing scheme and returned in newHash. You should use this to upgrade any
// stored password hash in your database.
//
// newHash is empty if the password was not valid or if no upgrade is required.
//
// You should treat any non-nil err as a password verification error.
func (ctx *Context) Verify(password, hash string) (newHash string, err error) {
	ctx.init()
	cVerifyCalls.Add(1)

	for i, scheme := range ctx.Schemes {
		if scheme.SupportsStub(hash) {
			newHash, err = scheme.Verify(password, hash)
			if err == nil {
				cSuccessfulVerifyCalls.Add(1)
				if i != 0 {
					cSuccessfulVerifyCallsWithUpgrade.Add(1)

					// If the scheme is not the first scheme, rehash with the preferred
					// scheme.
					newHash, err = ctx.Hash(password, "")
				}
			} else {
				cFailedVerifyCalls.Add(1)
			}

			return
		}
	}

	err = abstract.ErrUnsupportedScheme
	return
}

// Determines whether a stub or hash needs updating according to the policy of
// the context.
func (ctx *Context) NeedsUpdate(stub string) bool {
	ctx.init()

	for _, scheme := range ctx.Schemes {
		if scheme.SupportsStub(stub) {
			return scheme.NeedsUpdate(stub)
		}
	}

	return false
}

// The default context, which uses sensible defaults. Most users should not
// reconfigure this. The defaults may change over time, so you may wish
// to reconfigure the context or use a custom context if you want precise
// control over the hashes used.
var DefaultContext Context

// Hashes a UTF-8 plaintext password using the default context and produces a
// password hash. Chooses the preferred password hashing scheme based on the
// configured policy. The default policy is sensible.
func Hash(password string) (hash string, err error) {
	return DefaultContext.Hash(password, "")
}

// Verifies a UTF-8 plaintext password using a previously derived password hash
// and the default context. Returns nil err only if the password is valid.
//
// If the hash is determined to be deprecated based on policy, and the password
// is valid, the password is hashed using the preferred password hashing scheme
// and returned in newHash. You should use this to upgrade any stored password
// hash in your database.
//
// newHash is empty if the password was invalid or no upgrade is required.
//
// You should treat any non-nil err as a password verification error.
func Verify(password, hash string) (newHash string, err error) {
	return DefaultContext.Verify(password, hash)
}

// Uses the default context to determine whether a stub or hash needs updating.
func NeedsUpdate(stub string) bool {
	return DefaultContext.NeedsUpdate(stub)
}

// © 2008-2012 Assurance Technologies LLC.  (Python passlib)  BSD License
// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
