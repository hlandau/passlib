// Package passlib provides a simple password hashing and verification
// interface abstracting multiple password hashing schemes.
//
// Most people need concern themselves only with the functions Hash
// and Verify, which uses the default context and sensible defaults.
package passlib // import "gopkg.in/hlandau/passlib.v1"

import "gopkg.in/hlandau/passlib.v1/abstract"
import "gopkg.in/hlandau/passlib.v1/hash/scrypt"
import "gopkg.in/hlandau/passlib.v1/hash/sha2crypt"
import "gopkg.in/hlandau/passlib.v1/hash/bcryptsha256"
import "gopkg.in/hlandau/passlib.v1/hash/bcrypt"
import "gopkg.in/hlandau/easymetric.v1/cexp"

var cHashCalls = cexp.NewCounter("passlib.ctx.hashCalls")
var cVerifyCalls = cexp.NewCounter("passlib.ctx.verifyCalls")
var cSuccessfulVerifyCalls = cexp.NewCounter("passlib.ctx.successfulVerifyCalls")
var cFailedVerifyCalls = cexp.NewCounter("passlib.ctx.failedVerifyCalls")
var cSuccessfulVerifyCallsWithUpgrade = cexp.NewCounter("passlib.ctx.successfulVerifyCallsWithUpgrade")
var cSuccessfulVerifyCallsDeferringUpgrade = cexp.NewCounter("passlib.ctx.successfulVerifyCallsDeferringUpgrade")

// The default schemes, most preferred first. The first scheme will be used to
// hash passwords, and any of the schemes may be used to verify existing
// passwords. The contents of this value may change with subsequent releases.
var DefaultSchemes = []abstract.Scheme{
	scrypt.SHA256Crypter,
	sha2crypt.Crypter256,
	sha2crypt.Crypter512,
	bcryptsha256.Crypter,
	bcrypt.Crypter,
}

// It is strongly recommended that you call this function like this before using passlib:
//
//   passlib.UseDefaults("YYYYMMDD")
//
// where YYYYMMDD is a date. This will be used to select the preferred scheme
// to use. If you do not call UseDefaults, the preferred scheme (the first item
// in the default schemes list) current as of 2016-09-22 will always be used,
// meaning that upgrade will not occur even when a better scheme is now
// available.
//
// Note that even if you don't call this function, new schemes will still be
// added to DefaultSchemes over time as non-initial values (items not at index
// 0), so servers will always, by default, be able to validate all schemes
// which passlib supports at any given time.
//
// The reason you must call this function is as follows: If passlib is deployed
// as part of a web application in a multi-server deployment, and passlib is
// updated, and the new version of that application with the updated passlib is
// deployed, that upgrade process is unlikely to be instantaneous. Old versions
// of the web application may continue to run on some servers. If merely
// upgrading passlib caused password hashes to be upgraded to the newer scheme
// on login, the older daemons may not be able to validate these passwords and
// users may have issues logging in. Although this can be ameliorated to some
// extent by introducing a new scheme to passlib, waiting some months, and only
// then making this the default, this could still cause issued if passlib is
// only updated very occasionally.
//
// Thus, you should update your call to UseDefaults only when all servers have
// been upgraded, and it is thus guaranteed that they will all be able to
// verify the new scheme. Making this value loadable from a configuration file
// is recommended.
//
// If you are using a single-server configuration, you can use the special
// value "latest" here (or, equivalently, a date far into the future), which
// will always use the most preferred scheme. This is hazardous in a
// multi-server environment.
//
// The constants beginning 'DefaultsVersion' in this package document dates
// which are meaningful to this function. The constant values they are equal to
// will never change, so there is no need to use them instead of string
// literals, although you may if you wish; they are intended mainly as
// documentation as to the significance of various dates.
//
// Example:
//
//   passlib.UseDefaults("20160922")
//
func UseDefaults(date string) {
	// The schemes haven't changed yet, so currently this does nothing.
}

// This is the first and current set of defaults used by passlib. It prefers
// scrypt-sha256.
const DefaultsVersion20160922 = "20160922"

// A password hashing context, that uses a given set of schemes to hash and
// verify passwords.
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

func (ctx *Context) schemes() []abstract.Scheme {
	if ctx.Schemes == nil {
		return DefaultSchemes
	}

	return ctx.Schemes
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
func (ctx *Context) Hash(password string) (hash string, err error) {
	cHashCalls.Add(1)

	return ctx.schemes()[0].Hash(password)
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
	return ctx.verify(password, hash, true)
}

// Like Verify, but does not hash an upgrade password when upgrade is required.
func (ctx *Context) VerifyNoUpgrade(password, hash string) error {
	_, err := ctx.verify(password, hash, false)
	return err
}

func (ctx *Context) verify(password, hash string, canUpgrade bool) (newHash string, err error) {
	cVerifyCalls.Add(1)

	for i, scheme := range ctx.schemes() {
		if !scheme.SupportsStub(hash) {
			continue
		}

		err = scheme.Verify(password, hash)
		if err != nil {
			cFailedVerifyCalls.Add(1)
			return "", err
		}

		cSuccessfulVerifyCalls.Add(1)
		if i != 0 || scheme.NeedsUpdate(hash) {
			if canUpgrade {
				cSuccessfulVerifyCallsWithUpgrade.Add(1)

				// If the scheme is not the first scheme, try and rehash with the
				// preferred scheme.
				if newHash, err2 := ctx.Hash(password); err2 == nil {
					return newHash, nil
				}
			} else {
				cSuccessfulVerifyCallsDeferringUpgrade.Add(1)
			}
		}

		return "", nil
	}

	return "", abstract.ErrUnsupportedScheme
}

// Determines whether a stub or hash needs updating according to the policy of
// the context.
func (ctx *Context) NeedsUpdate(stub string) bool {
	for i, scheme := range ctx.schemes() {
		if scheme.SupportsStub(stub) {
			return i != 0 || scheme.NeedsUpdate(stub)
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
	return DefaultContext.Hash(password)
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

// Like Verify, but never upgrades.
func VerifyNoUpgrade(password, hash string) error {
	return DefaultContext.VerifyNoUpgrade(password, hash)
}

// Uses the default context to determine whether a stub or hash needs updating.
func NeedsUpdate(stub string) bool {
	return DefaultContext.NeedsUpdate(stub)
}

// © 2008-2012 Assurance Technologies LLC.  (Python passlib)  BSD License
// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
