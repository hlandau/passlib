package pbkdf2

import "testing"

type test struct {
	password string
	hash     string
}

var test_sha1 = []test{
	{"", "$pbkdf2$131000$rpVyDoFwDoHwfi8FAGBMqQ$KzxgTFYx.WC8y3G7T.ZRNC16BDs"},
	{"a", "$pbkdf2$131000$6h0jhHAuRSjF2DsnJOT8Hw$iXVE/hRu6mhyxsfGiTVZgBAiWJg"},
	{"ab", "$pbkdf2$131000$sXbunfP.n3PufQ9BSMkZow$rrEl2XYXDwLnHF/7AwSVCq8WCr4"},
	{"abc", "$pbkdf2$131000$bW0tJaT03huD8F6LcU4pRQ$dtV.m979atKXoe8dNNpMa43Gips"},
	{"abcd", "$pbkdf2$131000$2btXqhWCEKLU.p.TUurd.w$G3eQnQiG/BFRU.F4XqwUBPR8O2E"},
	{"abcde", "$pbkdf2$131000$gzDm3PsfA2BMaW3tHaO0Ng$oHF5I8Id58OCLTTUKElczL2oQJ8"},
	{"abcdef", "$pbkdf2$131000$pVSKkdJaS6nV.v/fe29NCQ$ruqeF1RLQsa5bESBa3Wvm0/7vEU"},
	{"abcdefg", "$pbkdf2$131000$FWIshVCqVSolxHgvhdD6/w$W3dxvb8s8/7srAorKOllpLcYFGA"},
	{"abcdefgh", "$pbkdf2$131000$nLNWqvWeU4qRMobwHkOodQ$bKEjhNS2UVYj9Id1v0y7/vSgtPM"},
	{"abcdefghi", "$pbkdf2$131000$pNS6V.o9B2AsxRjD.D.nFA$/b.TnvXwHn9gvL7oGw77UO6x4B4"},
	{"abcdefghij", "$pbkdf2$131000$EkLIWavVunfOeS/FWCvlfA$c8LtgafQyu2YPJ7KaVYFVFQhXQg"},
	{"abcdefghijk", "$pbkdf2$131000$a835PwdgDAGA0BqDEEIoZQ$Q3Lj40rPoYw6zOr7MXCbKe.SgFA"},
	{"abcdefghijkl", "$pbkdf2$131000$n/NeqxWidO5da.1dixEihA$pwWmr/A.RDaydHcBR9izZL2c20M"},
	{"abcdefghijklm", "$pbkdf2$131000$Z8y5t1ZKaa1VCsFY613LWQ$19yrjsbACj.14/FHILQKngksibo"},
	{"abcdefghijklmn", "$pbkdf2$131000$KIUQQiiFsFZq7T1nDMG49w$MPV8Fx/km0tfKd73m1opskTA4vU"},
	{"abcdefghijklmno", "$pbkdf2$131000$.d8bI6RUaq21ViplzDmHcA$7SZbV7nf5aewrQBGF4g0PRRM/Fg"},
	{"abcdefghijklmnop", "$pbkdf2$131000$ba219v6fMyYEAGAsxdi7dw$eVNXt/0ljC8v.WVhLQB167TiUy4"},
	{"qrstuvwxyz012345", "$pbkdf2$131000$FCIkhDCGsBZiDEGIcW7NOQ$VK6RSOHwVEB0WlzR2HzoZcJp02Y"},
	{"67890./", "$pbkdf2$131000$FAKAMGas9X5vDaF0TkkJ4Q$Z7RUXPH2IdhH2FEfbSHfkBS8ZIU"},
	{"ABCDEFGHIJKLMNOP", "$pbkdf2$131000$k/IeQ0iJkVJKCUEIgXCOEQ$zZDBIa8T7jG//e8ITciUIHjqfdM"},
	{"QRSTUVWXYZ012345", "$pbkdf2$131000$LmXs/R9jbM2Z8967N2ZsDQ$rwr7vtpJWCiz.lAy9rzF.WztLqw"},
}

var test_sha256 = []test{
	{"", "$pbkdf2-sha256$29000$FeKc8773HmOMcW7tHUPo/Q$Xc31n0kWSaQd7xXJkR0O5W7vHXVCLfKNdKsgiBW.aYc"},
	{"a", "$pbkdf2-sha256$29000$FoKQshaCUMo5B6AUwpjT.g$dosGQILQixtDqR1Zh2.GowEngJ59lWPivBGptx32960"},
	{"ab", "$pbkdf2-sha256$29000$8p5zrhUCIGQMoVRKqZVyzg$O.z4CN4JlPJltIZMzS6bi6YtRH.WfeDvPFCA7Z24o1M"},
	{"abc", "$pbkdf2-sha256$29000$2dsbYwxhzDlHqBWCMObc2w$GYnQVBLHvbjzDpZdOY8lZtkrE8lqbZ3zURM9rXMZv1A"},
	{"abcd", "$pbkdf2-sha256$29000$PieklNJ6z5lzLqU0hhAC4A$E/M477bliAuTGt.b/9Yf4gIsb4.MKXQsO4k1F26BoHw"},
	{"abcde", "$pbkdf2-sha256$29000$WKv1Puc8R4hx7v3/3xvDWA$U9WfYB1Y1EdIkkmbyxkagOaO5ZHiDJKDeMKpySNkpNA"},
	{"abcdef", "$pbkdf2-sha256$29000$cu59zznn3HsvpRSi1HoPwQ$U28XO37KiGT1rfiN1AtmMq5wc9FsqjK4hEPLgKpaCWM"},
	{"abcdefg", "$pbkdf2-sha256$29000$2Nu71zon5BzjvDfGOMdYiw$U7uoKXZVYcwWQ26osBlr3BRpI71/wF52L3nHUmUI4eU"},
	{"abcdefgh", "$pbkdf2-sha256$29000$BGDMeW9tjVFKiREihPD./w$6L38QVvEr4xAN4iUunumpyfcu64ym4n/cBhDu1Y5a.4"},
	{"abcdefghi", "$pbkdf2-sha256$29000$HeN8b42RsjYGAKDUuhdizA$aMOAAuZyr48CIGEKbaEsnvxPBXDSvNKT2nsz5we2IVg"},
	{"abcdefghij", "$pbkdf2-sha256$29000$5vwfo7RWCmHsvVdKibH23g$IJsvPxtO6HqBhGdwbxE33FvqC0eN6vzHfPJTdvgbf9o"},
	{"abcdefghijk", "$pbkdf2-sha256$29000$KwUgROj9nzMGwHiP8X7vfQ$TS4L1KqPKeX7nFZYC8aZ3zo3R/D2w5uqDIx0Qn4OEdA"},
	{"abcdefghijkl", "$pbkdf2-sha256$29000$IkSI0dq7F0KoVUrpvRfiPA$bHh6iwlRwBlrwgpZgt9z7dmSY1QvVLk95CwxjeiJ8KI"},
	{"abcdefghijklm", "$pbkdf2-sha256$29000$LgWAcM55z1kLIcS4935vzQ$b1lkgvjoooyXbJdSlZnva8SHb5IV/e69ReD1c9jHjP8"},
	{"abcdefghijklmn", "$pbkdf2-sha256$29000$652TMmas1VoLQej9H4NQag$HuexmPWNkzQP6gMsPvFn2y1gMHDJC/f5WsSpCaJeXRk"},
	{"abcdefghijklmno", "$pbkdf2-sha256$29000$dc55LwWgtNb63xtDiNF6rw$ndx1bqOEDP93yUxcf/LqvoxljKpdWuVMQAlkM9qZO4g"},
	{"abcdefghijklmnop", "$pbkdf2-sha256$29000$eK.1NobQWosxphRi7F2LcQ$tI.aL90NRMAyK/8HdDbVzsmBI1uymAUi/5b0xBwNCog"},
	{"qrstuvwxyz012345", "$pbkdf2-sha256$29000$i3EuRQiBMEZIiTEmBEBobQ$EhWgevRpzypjSLsRtxKAXtSBAIjArS8Ckhxh/43j024"},
	{"67890./", "$pbkdf2-sha256$29000$gvAewzintLYWwphTqjWGkA$Y7vNdsWTeZCv/l/qyiRbG6JPRji0bY/lANT15anr1cc"},
	{"ABCDEFGHIJKLMNOP", "$pbkdf2-sha256$29000$41xrDUGI8d5ba81Z673Xmg$ywz5c/jLFSeJ6qjC8AMoJe7wgtnP0FMC7pZ4Ku6ja6U"},
	{"QRSTUVWXYZ012345", "$pbkdf2-sha256$29000$S2kNwXhPqbUWojRGSMn5Hw$hvNURMsr8AFlhaIeRhJRVFXirtbNdWvPjB0z24rTTG8"},
}

var test_sha512 = []test{
	{"", "$pbkdf2-sha512$25000$Rug9hxCCEAJAqBXCeO99rw$Z5cLeLLbcEHdv.LQzFi86iEVtMDdkKD8eI1b4JynptuWazoGEi/dkOmbD0211BXiKMlMPDBaDjqbp2xAelpSAQ"},
	{"a", "$pbkdf2-sha512$25000$nPN.D2FMKUUopXSudY4xpg$5wB78x5VWeeXvIscWZNQZOmMiVN9s1UDSC58tLd8z9PF.KFCZYzpPy/kT0DFMhaMEUgzhX0rC8LYSVVl1cuJDw"},
	{"ab", "$pbkdf2-sha512$25000$5XxvDYFQqnUOQWhNKeV8Tw$hhHStXAyVWsa7GFMD0oHk1.hI6iYN7MDRx5zhvfcCUV.Hmh3xuezYAkgHQAN1yBdW9eO6p/6cDSj7fmr0AtIhw"},
	{"abc", "$pbkdf2-sha512$25000$29s7h1BqzZnT.n8vBUDIGQ$80zmUh1Ytb8Gd1T.ik/eaFELNmu9gKUZYZZGlm15xqgHSSYvJTYZteFoy5qmAEdSSroYhFLFxW9IGn7lEqY2Sw"},
	{"abcd", "$pbkdf2-sha512$25000$.997D8F4D.G8dw6BMCbEeA$pWOT1dKN8rrA6WubYdrFHkYyvIsAiAJ1JeqoJ1KxvDqP4LUqflgpYUiLfSa0DNliIIrhmKDUTWncXprO57EnEA"},
	{"abcde", "$pbkdf2-sha512$25000$7r1XSqkV4hzj3BsjBOA8Zw$sq9G8ZfZG1g4OGidpElHT7yqanrO9FsgPYY131hAma.LcXuXJybY1mC3Q8XzkDafvngIynOuGl8NDueT481jWA"},
	{"abcdef", "$pbkdf2-sha512$25000$yZnz3ttbq7XW2ruX0tq7tw$8O2TVXrSHNopS3t7uuh/Wl6Hnhf7p4sF78hiYeNzhV5UFFf4Iah93IkHvmycaC3bipGFCoHUzcTNkRiO/AnAMw"},
	{"abcdefg", "$pbkdf2-sha512$25000$Zsw551yLsbb2ntM6J2SsdQ$DrcS6jDeOsZs0yNXvqjioXoRL9EI4vEbrX.CNsIGtd9p5fkn1AO4vcnkjrRj1ZPXFgn0gTu8vQiQg1fDgfSiAg"},
	{"abcdefgh", "$pbkdf2-sha512$25000$FOK8N6Y0xpjzPgdgLKVUSg$jTdoR/ns0CimsLGUjkImjL7dW41xoMKBVjE/CAuPPokMhk9178E2wnaMJ7JJ9gw9ipCPPrICdLzASzmwccgSXg"},
	{"abcdefghi", "$pbkdf2-sha512$25000$7H2vNeacE0IoZQwBwNjbmw$pcMYQMOjFpnuxwdpEkXCId0jWZpnZkf.UGRSemOvfYUqmxt1aa0eXYmZ8cMB5PkhWmsBkOFCPC8HcpfFTkBgtA"},
	{"abcdefghij", "$pbkdf2-sha512$25000$u5cyppSylvL.PyfEeE/JGQ$r1SuBURIVnuPYklue.VwmDTMSPm.KmE8pxUHjMkCTtBwm24DJyBdCtAt8a2SEwA0vgaYyJGN.z68/BvHItBjUg"},
	{"abcdefghijk", "$pbkdf2-sha512$25000$hXCuFULo/f8f41yrlXKOMQ$sCvKQH9qzEvsRk9snlR5Y8iVJ3j086jQ3a9p9V/QckWt7wVYcQZ03/Pg/j5n66PNMRNyorrtUa..8QHi/Pnu2A"},
	{"abcdefghijkl", "$pbkdf2-sha512$25000$nnNuba0VImQsJaT0/p.T8g$2HKbjVtAKSQVom8tiOzcd7RkqxefcCuxt9Y8zmwe2Lds6AvhytxAiOunHX2XE5u5LVnVsblcDvMjvvOlJ2Louw"},
	{"abcdefghijklm", "$pbkdf2-sha512$25000$A2AsReh9zzmHUOqd894bAw$HwnOfFfIaabQ5WeehDfxq5RLPCnXfK9FrxmLESF.dy7PRNyFiJ1HPOBTFVa9I1rMiEKJCy0kzZuhW8IlOJbwsw"},
	{"abcdefghijklmn", "$pbkdf2-sha512$25000$HsM45zzHGMO4995bizFmDA$DG9b4H10vBG.1kdu0pP6RHEeem3/KMCIPKGpKjHhjyWyricpqxPcXZD2ZtcTjQtnuIHhoauIJFHLQXnEOBwC5Q"},
	{"abcdefghijklmno", "$pbkdf2-sha512$25000$Mab0HsOYM0boXct5r7U2xg$zWyjCu4pIvhPv65xgGRCfU2I3GuF0wWHXCpvvdTDIzmY.stNRWFZ1GncCz4G0NzNsINBgCkoHsZQIkJr6Ca4UQ"},
	{"abcdefghijklmnop", "$pbkdf2-sha512$25000$O4fwPmdMyRmDUIrx/h9jTA$Xlp267ZwEbG4aOpN3Bve/ATo3rFA7WH8iMdS16Xbe9rc6P5welk1yiXEMPy7.BFp0qsncipHumaW1trCWVvq/A"},
	{"qrstuvwxyz012345", "$pbkdf2-sha512$25000$XUvJmdNaK8V4z5mTkhICQA$oPcqbiUfaM/IzPcbEEDl9LUMOegfq65fOzdsYUUxU44ops2k91yCprer94a9xXNLSnRRvsZ65wyodFGqnfZ.Pg"},
	{"67890./", "$pbkdf2-sha512$25000$sPZey1lr7T0nZAwBoFTKWQ$y4Y.OYBwnBO6JGP3C5XjipvwBNanCIQUoa1HL2zaU7b3YsoZ5hKOLdTkDjoup2NVOmJQ1QosgkeLGuycm1vXEw"},
	{"ABCDEFGHIJKLMNOP", "$pbkdf2-sha512$25000$7f0/R4jRGmNMidF6713L2Q$XFlwZrQhqT1xZzZKm9YS5FgRkrGvFeToU5V.Bdxhm9ROXWHOoSgRV2bUrRvAAh.9Ob7TKPvZ1ERxjBLH2Chc4Q"},
	{"QRSTUVWXYZ012345", "$pbkdf2-sha512$25000$k/K.V4px7p3zvneuVcoZ4w$u8s2Co25ybjqZHhtEeio10ksQ/Tvo.wYoLNbTfwjGF4gXq3xY.mULeH6jVOxjP7bZv0qMaO79FQ3maXAoo.Yww"},
}

func TestPBKDF2_SHA1(t *testing.T) {
	var crypter = SHA1Crypter
	var test_hashes = test_sha1

	{
		ok := crypter.SupportsStub(test_hashes[0].hash)
		if !ok {
			t.Errorf("crypter reports not support valid stub")
		}

		ok = crypter.SupportsStub("$pbkdf234") // this isn't valid
		if ok {
			t.Errorf("crypter reports supporting invalid stub")
		}
	}

	{
		// do a simple test of hashing and verifying within Go
		hash, err := crypter.Hash("helloworld")
		if err != nil {
			t.Errorf("recieved error whilst hashing password: %v\n", err)
		}

		// should be valid
		err = crypter.Verify("helloworld", hash)
		if err != nil {
			t.Errorf("valid password not accepted: %v\n", err)
		}

		// should not be valid
		err = crypter.Verify("goodbyeuniverse", hash)
		if err == nil {
			t.Errorf("invalid password accepted\n")
		}
	}

	{
		// run through some python passlib generated passwords and verify them to ensure cross comparability
		for _, test := range test_hashes {
			err := crypter.Verify(test.password, test.hash)
			if err != nil {
				t.Errorf("unable to verify password %s: %v", test.password, err)
			}
		}
	}
}

func TestPBKDF2_SHA256(t *testing.T) {
	var crypter = SHA256Crypter
	var test_hashes = test_sha256

	{
		ok := crypter.SupportsStub(test_hashes[0].hash)
		if !ok {
			t.Errorf("crypter reports not support valid stub")
		}

		ok = crypter.SupportsStub("$pbkdf234") // this isn't valid
		if ok {
			t.Errorf("crypter reports supporting invalid stub")
		}
	}

	{
		// do a simple test of hashing and verifying within Go
		hash, err := crypter.Hash("helloworld")
		if err != nil {
			t.Errorf("recieved error whilst hashing password: %v\n", err)
		}

		// should be valid
		err = crypter.Verify("helloworld", hash)
		if err != nil {
			t.Errorf("valid password not accepted: %v\n", err)
		}

		// should not be valid
		err = crypter.Verify("goodbyeuniverse", hash)
		if err == nil {
			t.Errorf("invalid password accepted\n")
		}
	}

	{
		// run through some python passlib generated passwords and verify them to ensure cross comparability
		for _, test := range test_hashes {
			err := crypter.Verify(test.password, test.hash)
			if err != nil {
				t.Errorf("unable to verify password %s: %v", test.password, err)
			}
		}
	}
}

func TestPBKDF2_SHA512(t *testing.T) {
	var crypter = SHA512Crypter
	var test_hashes = test_sha512

	{
		ok := crypter.SupportsStub(test_hashes[0].hash)
		if !ok {
			t.Errorf("crypter reports not support valid stub")
		}

		ok = crypter.SupportsStub("$pbkdf234") // this isn't valid
		if ok {
			t.Errorf("crypter reports supporting invalid stub")
		}
	}

	{
		// do a simple test of hashing and verifying within Go
		hash, err := crypter.Hash("helloworld")
		if err != nil {
			t.Errorf("recieved error whilst hashing password: %v\n", err)
		}

		// should be valid
		err = crypter.Verify("helloworld", hash)
		if err != nil {
			t.Errorf("valid password not accepted: %v\n", err)
		}

		// should not be valid
		err = crypter.Verify("goodbyeuniverse", hash)
		if err == nil {
			t.Errorf("invalid password accepted\n")
		}
	}

	{
		// run through some python passlib generated passwords and verify them to ensure cross comparability
		for _, test := range test_hashes {
			err := crypter.Verify(test.password, test.hash)
			if err != nil {
				t.Errorf("unable to verify password %s: %v", test.password, err)
			}
		}
	}
}

func BenchmarkPBDF2_SHA1_Hash(b *testing.B) {
	var crypter = SHA1Crypter
	const passwd = "benchmarkMeThis!!"

	for i := 0; i < b.N; i++ {
		crypter.Hash(passwd)
	}
}

func BenchmarkPBDF2_SHA1_Verify(b *testing.B) {
	var crypter = SHA1Crypter
	const passwd = "benchmarkMeThis!!"
	var hash, _ = crypter.Hash(passwd)

	for i := 0; i < b.N; i++ {
		crypter.Verify(passwd, hash)
	}
}

func BenchmarkPBDF2_SHA256_Hash(b *testing.B) {
	var crypter = SHA256Crypter
	const passwd = "benchmarkMeThis!!"

	for i := 0; i < b.N; i++ {
		crypter.Hash(passwd)
	}
}

func BenchmarkPBDF2_SHA256_Verify(b *testing.B) {
	var crypter = SHA256Crypter
	const passwd = "benchmarkMeThis!!"
	var hash, _ = crypter.Hash(passwd)

	for i := 0; i < b.N; i++ {
		crypter.Verify(passwd, hash)
	}
}

func BenchmarkPBDF2_SHA512_Hash(b *testing.B) {
	var crypter = SHA512Crypter
	const passwd = "benchmarkMeThis!!"

	for i := 0; i < b.N; i++ {
		crypter.Hash(passwd)
	}
}

func BenchmarkPBDF2_SHA512_Verify(b *testing.B) {
	var crypter = SHA512Crypter
	const passwd = "benchmarkMeThis!!"
	var hash, _ = crypter.Hash(passwd)

	for i := 0; i < b.N; i++ {
		crypter.Verify(passwd, hash)
	}
}
