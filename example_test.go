package passlib

// User signup example.
func ExampleHash_signup() {
	// User signup example.
	// NOTE: Call UseDefaults at application initialisation time to initialise
	// passlib before using Hash() or Verify(). See func UseDefaults.

	// ... signup code ...

	// Get the password the user chose by whatever means.
	password := getSignupPassword()
	username := getSignupUsername()

	hash, err := Hash(password)
	if err != nil {
		// couldn't hash password for some reason
		return
	}

	// hash now contains a hash in modular crypt form.
	// Store hash in database, etc.
	storeHashInDatabase(username, hash)
}

// User login example.
func ExampleVerify_login() {
	// User login example.
	// NOTE: Call UseDefaults at application initialisation time to initialise
	// passlib before using Hash() or Verify(). See func UseDefaults.

	// Get the password for the user we have stored in the database.
	hash := getUserHashFromDatabase()

	// Get the plaintext password the user tried to login with.
	password := getLoginPassword()

	newHash, err := Verify(password, hash)
	if err != nil {
		// Incorrect password, malformed hash, etc.
		return
	}

	if newHash != "" {
		// passlib thinks we should upgrade to a new stronger hash.
		// ... store the new hash in the database ...
	}

	// ... log the user in ...
}

// These are dummy functions for the benefit of the examples.

func getSignupUsername() string {
	return ""
}

func getSignupPassword() string {
	return "password"
}

func getLoginPassword() string {
	return "password"
}

func storeHashInDatabase(username, hash string) {
}

func getUserHashFromDatabase() string {
	return ""
}
