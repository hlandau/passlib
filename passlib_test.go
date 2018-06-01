package passlib

import (
	"testing"

	"gopkg.in/hlandau/passlib.v1/abstract"
	"gopkg.in/hlandau/passlib.v1/hash/argon2"
	"gopkg.in/hlandau/passlib.v1/hash/bcrypt"
	"gopkg.in/hlandau/passlib.v1/hash/bcryptsha256"
	"gopkg.in/hlandau/passlib.v1/hash/scrypt"
	"gopkg.in/hlandau/passlib.v1/hash/sha2crypt"
)

//import "gopkg.in/hlandau/passlib.v1/hash/scrypt"

func TestPasslib(t *testing.T) {
	for _, scheme := range DefaultSchemes {
		//t.Logf("scheme: %+v\n", scheme)
		c := Context{Schemes: []abstract.Scheme{scheme}}

		h, err := c.Hash("password")
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		newHash, err := c.Verify("password", h)
		if err != nil {
			t.Fatalf("err verifying: %v (%#v)", err, h)
		}
		if newHash != "" {
			t.Fatalf("non-empty newHash with hash just created")
		}

		newHash, err = c.Verify("password2", h)
		if err == nil {
			t.Fatalf("got nil error with wrong password")
		}
		if newHash != "" {
			t.Fatalf("non-empty newHash with wrong password")
		}
	}
}

func TestDefault(t *testing.T) {
	h, err := Hash("password")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	newHash, err := Verify("password", h)
	if err != nil {
		t.Fatalf("err verifying: %v (%#v)", err, h)
	}

	if newHash != "" {
		t.Fatalf("unexpected upgrade")
	}
	newHash, err = Verify("foobar", "$s2$16384$8$1$qa9lVfhmTE8F2Jpwya9m7uoE$Q7dSPqhZQCLWpjniaz7RVm+xorpSAPTvOCP2uoZmoiI=")
	//$argon2i$v=19$m=32768,t=4,p=4$c29tZXNhbHRzb21lYWxrdA$HcTlbOnOAzJ2dUrlgHnNwC0yallJ/Gl2NbAWqg4IukA")
	if err != nil {
		t.Fatalf("err verifying known good: %v", err)
	}

	if newHash != "" {
		t.Fatalf("unexpected upgrade")
	}

	// Now test new defaults.
	UseDefaults(Defaults20180601)

	newHash, err = Verify("foobar", "$argon2i$v=19$m=32768,t=4,p=4$c29tZXNhbHRzb21lYWxrdA$HcTlbOnOAzJ2dUrlgHnNwC0yallJ/Gl2NbAWqg4IukA")
	if err != nil {
		t.Fatalf("err verifying known good: %v", err)
	}

	if newHash != "" {
		t.Fatalf("unexpected upgrade")
	}

	// Switch back.
	UseDefaults(Defaults20160922)
}

func TestUpgrade(t *testing.T) {
	c := Context{Schemes: DefaultSchemes[1:]}

	h, err := c.Hash("password")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	newHash, err := Verify("password", h)
	if err != nil {
		t.Fatalf("err verifying: %v (%#v)", err, h)
	}
	if newHash == "" {
		t.Fatalf("empty newHash when verifying deprecated hash")
	}

	newHash2, err := Verify("password", newHash)
	if err != nil {
		t.Fatalf("err verifying after upgrade: %v", err)
	}
	if newHash2 != "" {
		t.Fatalf("non-empty newHash after upgrade")
	}
}

func kat(t *testing.T, scheme abstract.Scheme, password, hash string) {
	c := Context{Schemes: []abstract.Scheme{scheme}}

	_, err := c.Verify(password, hash)

	if err != nil {
		t.Logf("err verifying known good hash: %v %s %s", scheme, password, hash)
		t.Fail()
	}

	_, err = c.Verify(" "+password, hash)
	if err == nil {
		t.Logf("invalid verification of known hash: %v", scheme)
		t.Fail()
	}
}

func TestKat(t *testing.T) {
	for _, v := range []struct{ p, h string }{
		{"foobar", "$5$rounds=110000$J672cUm182wrK1bX$0TzjpY6NV07r82J9YebG50dZuwHoQWrny9Q7y6ceO7/"},
		// From passlib 1.6: from JTR 1.7.9
		{"U*U*U*U*", "$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9"},
		{"U*U***U", "$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd."},
		{"U*U***U*", "$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A"},
		{"*U*U*U*U", "$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA"},
		{"", "$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43"},
		// From passlib 1.6: custom tests
		{"", "$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3"},
		{" ", "$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH."},
		{"test", "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1"},
		{"Compl3X AlphaNu3meric", "$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB"},
		{"4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#", "$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7"},
		{"with unic\u00D6de", "$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4"},
		// From passlib 1.6: more tests
		{"secret", "$5$rounds=1004$nacl$oiWPbm.kQ7.jTCZoOtdv7/tO5mWv/vxw5yTqlBagVR7"},
		{"secret", "$5$rounds=1005$nacl$6Mo/TmGDrXxg.bMK9isRzyWH3a..6HnSVVsJMEX7ud/"},
		{"secret", "$5$rounds=1006$nacl$I46VwuAiUBwmVkfPFakCtjVxYYaOJscsuIeuZLbfKID"},
		{"secret", "$5$rounds=1007$nacl$9fY4j1AV3N/dV/YMUn1enRHKH.7nEL4xf1wWB6wfDD4"},
		{"secret", "$5$rounds=1008$nacl$CiFWCfn8ODmWs0I1xAdXFo09tM8jr075CyP64bu3by9"},
		{"secret", "$5$rounds=1009$nacl$QtpFX.CJHgVQ9oAjVYStxAeiU38OmFILWm684c6FyED"},
		{"secret", "$5$rounds=1010$nacl$ktAwXuT5WbjBW/0ZU1eNMpqIWY1Sm4twfRE1zbZyo.B"},
		{"secret", "$5$rounds=1011$nacl$QJWLBEhO9qQHyMx4IJojSN9sS41P1Yuz9REddxdO721"},
		{"secret", "$5$rounds=1012$nacl$mmf/k2PkbBF4VCtERgky3bEVavmLZKFwAcvxD1p3kV2"},
	} {
		kat(t, sha2crypt.Crypter256, v.p, v.h) //"foobar", "$5$rounds=110000$J672cUm182wrK1bX$0TzjpY6NV07r82J9YebG50dZuwHoQWrny9Q7y6ceO7/")
	}

	for _, v := range []struct{ p, h string }{
		{"foobar", "$6$rounds=100000$Xp12SciZHbjtt67a$RE2cT9MkPR2GFq0rw2ADNIHvIqmj7EFL3K0d2ASe9bub5ANv8Xa4y6pm78pkAPcXoq0zJmSyIc7pqlioTuCdq/"},
		// From passlib 1.6: from JTR 1.7.9
		{"U*U*U*U*", "$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0"},
		{"U*U***U", "$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1"},
		{"U*U***U*", "$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/"},
		{"*U*U*U*U", "$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330"},
		{"", "$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN."},
		// From passilb 1.6: custom tests
		{"", "$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1"},
		{" ", "$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0"},
		{"test", "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1"},
		{"Compl3X AlphaNu3meric", "$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/"},
		{"4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#", "$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1"},
		// From passlib 1.6: ensures UTF-8 used for unicode
		{"t\u00e1\u0411\u2113\u0259", "$6$rounds=40000$PEZTJDiyzV28M3.m$GTlnzfzGB44DGd1XqlmC4erAJKCP.rhvLvrYxiT38htrNzVGBnplFOHjejUGVrCfusGWxLQCc3pFO0A/1jYYr0"},
	} {
		kat(t, sha2crypt.Crypter512, v.p, v.h)
	}

	for _, v := range []struct{ p, h string }{
		{"foobar", "$2a$12$R7THiKSJilzQRPcvtUCSu.WI.N3gT2TY5BxjTp6EDnPy40Sn84m4K"},
		// From passlib 1.6: from JTR 1.7.9
		{"U*U*U*U*", "$2a$05$c92SVSfjeiCD6F2nAD6y0uBpJDjdRkt0EgeC4/31Rf2LUZbDRDE.O"},
		{"U*U***U", "$2a$05$WY62Xk2TXZ7EvVDQ5fmjNu7b0GEzSzUXUh2cllxJwhtOeMtWV3Ujq"},
		{"U*U***U*", "$2a$05$Fa0iKV3E2SYVUlMknirWU.CFYGvJ67UwVKI1E2FP6XeLiZGcH3MJi"},
		{"*U*U*U*U", "$2a$05$.WRrXibc1zPgIdRXYfv.4uu6TD1KWf0VnHzq/0imhUhuxSxCyeBs2"},
		{"", "$2a$05$Otz9agnajgrAe0.kFVF9V.tzaStZ2s1s4ZWi/LY4sw2k/MTVFj/IO"},
		// From passlib 1.6: test vectors from http://www.openwall.com/crypt v1.2
		// Note that this omits any hashes that depend on crypt_blowfish's various
		// CVE-2011-2483 workarounds (hash 2a and \xFF\xFF in password, and any 2x
		// hashes); and only contain hashes which are correct under both
		// crypt_blowfish 1.2 AND OpenBSD.
		{"U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
		{"U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
		{"U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
		{"", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
		{"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored",
			"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"},
		{"\xa3", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
		{"\xff\xa3345", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e"},
		{"\xa3ab", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},
		{"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaachars after 72 are ignored as usual", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6"},
		{"\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU\xaaU", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy"},
		{"U\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xffU\xaa\xff", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe"},
		// From passlib 1.6: Keeping one of their 2y tests, because we are supporting that.
		{"\xa3", "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
		// From passlib 1.6: BSD wraparound bug (fixed in 2b)
		{"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123", "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi"},
		{"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234", "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi"},
		{"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345", "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi"},
		{"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456", "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi"},
		// From passlib 1.6: From py-bcrypt tests
		{"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
		{"a", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
		{"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
		{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
		// From passlib 1.6: Ensures UTF-8 used for unicode
		{"t\u00E1\u0411\u2113\u0259", "$2a$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG"},
		// From passlib 1.6: Ensure 2b support
		{"t\u00E1\u0411\u2113\u0259", "$2b$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG"},
	} {
		kat(t, bcrypt.Crypter, v.p, v.h)
	}

	for _, v := range []struct{ p, h string }{
		{"foobar", "$bcrypt-sha256$2a,12$rruXEyrqlhdwQf0tc75cyu$CI2KZzhhCtymN3OvZKF2axF4aJUq4x6"},

		// From passlib 1.6
		{"", "$bcrypt-sha256$2a,5$E/e/2AOhqM5W/KJTFQzLce$F6dYSxOdAEoJZO2eoHUZWZljW/e0TXO"},
		{"password", "$bcrypt-sha256$2a,5$5Hg1DKFqPE8C2aflZ5vVoe$12BjNE0p7axMg55.Y/mHsYiVuFBDQyu"},
		{"t\u00E1\u0411\u2113\u0259", "$bcrypt-sha256$2a,5$.US1fQ4TQS.ZTz/uJ5Kyn.$QNdPDOTKKT5/sovNz1iWg26quOU4Pje"},
		{"abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123", "$bcrypt-sha256$2a,5$X1g1nh3g0v4h6970O68cxe$r/hyEtqJ0teqPEmfTLoZ83ciAI1Q74."},
		{"abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123qwr", "$bcrypt-sha256$2a,5$X1g1nh3g0v4h6970O68cxe$021KLEif6epjot5yoxk0m8I0929ohEa"},
		{"abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123xyz", "$bcrypt-sha256$2a,5$X1g1nh3g0v4h6970O68cxe$7.1kgpHduMGEjvM3fX6e/QCvfn6OKja"},
	} {
		kat(t, bcryptsha256.Crypter, v.p, v.h)
	}

	for _, v := range []struct{ p, h string }{
		{"", "$s2$16384$8$1$5KHwLMZjMDiuPAhUYK/XcKZW$KZIGWg5XM1Xsh8X/wuBE1+KTeFImkuQn3gZpjUZcqns="},
		{"foobar", "$s2$16384$8$1$qa9lVfhmTE8F2Jpwya9m7uoE$Q7dSPqhZQCLWpjniaz7RVm+xorpSAPTvOCP2uoZmoiI="},
	} {
		kat(t, scrypt.SHA256Crypter, v.p, v.h)
	}

	for _, v := range []struct{ p, h string }{
		{"", "$argon2i$v=19$m=32768,t=4,p=4$XEfcwb81UQKSzIcxVEIgrw$1lAPOhgJpGJEgGSKxdnd3n3F9S5qPZSf53iKM1/SvTk"},
		{"foobar", "$argon2i$v=19$m=32768,t=4,p=4$uN6vgPBb8/liQld8lgFqew$KlvqGCHX7Cap0ohKY7YAUJsbzcnenCwvSAfhqtIA/Q0"},
	} {
		kat(t, argon2.Crypter, v.p, v.h)
	}
}

// © 2008-2012 Assurance Technologies LLC.  (Python passlib)  BSD License
// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
