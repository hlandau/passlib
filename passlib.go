package passlib
import "fmt"
import "github.com/hlandau/passlib/hash"

var ErrNoSupportedScheme = fmt.Errorf("no supported scheme found")
var DefaultSchemes = []hash.Scheme{ hash.SHA256Crypter }

type Context struct {
  // Slice of schemes to use, most preferred first.
  //
  // If left uninitialized, a sensible default set of schemes will be used.
  //
  // An upgrade hash (see the newHash return value of the Verify method of the
  // hash.Crypter interface) will be issued whenever a password is validated
  // using a scheme which is not the first scheme in this slice.
  Schemes []hash.Scheme
}

func (ctx *Context) init() {
  if len(ctx.Schemes) == 0 {
    ctx.Schemes = DefaultSchemes
  }
}

func (ctx *Context) MakeStub() (string, error) {
  ctx.init()
  
  return ctx.Schemes[0].MakeStub()
}

// Hashes a password. The input password should be UTF-8 plaintext.
// 
// If stub is "", one is generated automatically; you should specify stub as ""
// in almost all cases.
//
// The output is in modular crypt format.
func (ctx *Context) Hash(password, stub string) (hash string, err error) {
  ctx.init()

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

  err = ErrNoSupportedScheme
  return
}

// Tries to verify a password using a hash.
//
// The input password should be UTF-8 plaintext.
//
// You should treat any non-nil err as a password verification error.
//
// If the newHash return value is not an empty string, it is a more secure hash
// and you should replace the value in the database with that value.
func (ctx *Context) Verify(password, hash string) (newHash string, err error) {
  ctx.init()

  for i, scheme := range ctx.Schemes {
    if scheme.SupportsStub(hash) {
      newHash, err = scheme.Verify(password, hash)
      if err == nil && i != 0 {
        // If the scheme is not the first scheme, rehash with the preferred
        // scheme.
        newHash, err = ctx.Hash(password, "")
      }

      return 
    }
  }

  err = ErrNoSupportedScheme
  return
}

func (ctx *Context) NeedsUpdate(stub string) bool {
  ctx.init()

  for _, scheme := range ctx.Schemes {
    if scheme.SupportsStub(stub) {
      return scheme.NeedsUpdate(stub)
    }
  }

  return false
}

var DefaultContext Context

// Calculates a hash using the default context.
func Hash(password string) (hash string, err error) {
  return DefaultContext.Hash(password, "")
}

// Uses the default context to determine whether a stub needs updating.
func NeedsUpdate(stub string) bool {
  return DefaultContext.NeedsUpdate(stub)
}

// Verifies a password using the default context.
func Verify(password, hash string) (newHash string, err error) {
  return DefaultContext.Verify(password, hash)
}

// © 2008-2012 Assurance Technologies LLC.  (Python passlib)  BSD License
// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
