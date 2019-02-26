// Copyright (c) 2019 Ashish Kumar <akashish@iitk.ac.in>
// Copyright (c) 2019 Aniket Pandey <aniketp@iitk.ac.in>

package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib

	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v",
		errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// // The structure definition for a user record
// type User struct {
// 	Username string
// 	Password string

// 	// Some components for the private keys

// 	// You can add other fields here if you want...
// 	// Note for JSON to marshal/unmarshal, the fields need to
// 	// be public (start with a capital letter)
// }

/////////////////// Assignment

type PrivateKey = userlib.PrivateKey

type User_r struct {
	KeyAddr   string
	Signature []byte
	User
}

type User struct {
	Username string
	Password string
	Privkey  *PrivateKey
}

type Inode_r struct {
	KeyAddr   string
	Signature []byte
	Inode
}

type Inode struct {
	Filename     string
	ShRecordAddr string
	SymmKey      []byte
}

type SharingRecord_r struct {
	KeyAddr   string
	Signature []byte
	SharingRecord
}

type SharingRecord struct {
	Type       string
	MainAuthor string
	Address    []string
	SymmKey    [][]byte
}

type Data struct {
	KeyAddr   string
	Value     []byte
	Signature []byte
}

/////////////////

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Generate Key to store the encrypted User data
	passbyte := []byte(password + username)
	saltbyte := []byte(username + "user")

	// key = Argon2Key(password + username, username + "user", 10)
	keyHash := userlib.Argon2Key(passbyte, saltbyte, 10)
	marsh, err := json.Marshal(keyHash)
	if err != nil {
		userlib.DebugMsg("Key Marshal failed")
	}

	// This is the key where encrypted User struct will be stored
	userKey := hex.EncodeToString(marsh)
	userlib.DebugMsg(userKey)

	// Generate RSA Public-Private Key Pair for the User
	privKey, err := userlib.GenerateRSAKey()
	if err != nil {
		userlib.DebugMsg("RSA Key-Pair generation failed")
	}

	// Push the RSA Public Key to secure Key-Store
	userlib.KeystoreSet(username, privKey.PublicKey)

	// Generate a Key for symmetric encryption of User_r struct
	passbyte = []byte(username + password)
	saltbyte = []byte(username + "salt")

	// Symkey = Argon2Key(username + password, username + "salt", 10)
	symkeyHash := userlib.Argon2Key(passbyte, saltbyte, 10)
	userSymKey, err := json.Marshal(symkeyHash)
	if err != nil {
		userlib.DebugMsg("Marshal failed")
	}

	// This is the key to symmetrically encrypt User struct
	userlib.DebugMsg(hex.EncodeToString(userSymKey))

	// Initialize the User structure without any signature
	user := &User_r{
		KeyAddr: userKey, // The key at which this struct will be stored
		User: User{
			Username: username,
			Password: password,
			Privkey:  privKey,
		},
	}

	// Store the signature of User_r.User in User_r.Signature
	userMarsh, err := json.Marshal(user.User)
	if err != nil {
		userlib.DebugMsg("User_r.User Marshal failed")
	}
	mac := userlib.NewHMAC(userSymKey)
	mac.Write(userMarsh)
	user.Signature = mac.Sum(nil)

	// Finally, encrypt the whole thing
	user_rMarsh, err := json.Marshal(user)
	if err != nil {
		userlib.DebugMsg("User_r Marshal failed")
	}

	ciphertext := make([]byte, userlib.BlockSize+len(user_rMarsh))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))

	// userlib.DebugMsg("Random IV", hex.EncodeToString(iv))
	// NOTE: The "key" needs to be of 16 bytes
	cipher := userlib.CFBEncrypter(userSymKey[:16], iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(user_rMarsh))
	// userlib.DebugMsg("Message  ", hex.EncodeToString(ciphertext))

	// Push the encrypted data to Untrusted Data Store
	userlib.DatastoreSet(userKey, ciphertext)

	return &user.User, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Generate Key to retrieve the encrypted User data
	passbyte := []byte(password + username)
	saltbyte := []byte(username + "user")

	// key = Argon2Key(password + username, username + "user", 10)
	keyHash := userlib.Argon2Key(passbyte, saltbyte, 10)
	marsh, err := json.Marshal(keyHash)
	if err != nil {
		userlib.DebugMsg("Key Marshalling failed")
	}
	// This is the key where encrypted User struct is stored
	userKey := hex.EncodeToString(marsh)
	userlib.DebugMsg(userKey)

	//
	// Generate a Key for symmetric decryption of User_r struct
	passbyte = []byte(username + password)
	saltbyte = []byte(username + "salt")

	// Symkey = Argon2Key(username + password, username + "salt", 10)
	symkeyHash := userlib.Argon2Key(passbyte, saltbyte, 10)
	userSymKey, err := json.Marshal(symkeyHash)
	if err != nil {
		userlib.DebugMsg("Key Marshalling failed")
	}

	// This is the key to symmetrically encrypt User struct
	userlib.DebugMsg(hex.EncodeToString(userSymKey))

	//
	// Now, retrieve and decrypt the User_r struct and check if the
	// credentials and integrity are properly maintained.
	ciphertext, status := userlib.DatastoreGet(userKey)
	if status != true {
		return nil, errors.New("User not found")
	}

	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(userSymKey[:16], iv)

	// In place AES decryption of ciphertext
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	// userlib.DebugMsg("Decrypted message", string(ciphertext[userlib.BlockSize:]))

	var user User_r
	err = json.Unmarshal(ciphertext[userlib.BlockSize:], &user)
	if err != nil {
		userlib.DebugMsg("User_r Unmarshalling failed")
	}

	// Verify the User_r struct's integrity
	userMarsh, err := json.Marshal(user.User)
	if err != nil {
		userlib.DebugMsg("User_r.User Marshal failed")
	}

	mac := userlib.NewHMAC(userSymKey)
	mac.Write(userMarsh)
	if !userlib.Equal(user.Signature, mac.Sum(nil)) {
		return nil, errors.New("User Integrity check failed")
	}

	//
	// Cool, after verifying the integrity, cross check the credentials
	// just to be sure about user authentication
	if username != user.User.Username || password != user.User.Password {
		return nil, errors.New("Error: User credentials don't match")
	}

	if userKey != user.KeyAddr {
		return nil, errors.New("Error: Key-Value-Swap Attack")
	}

	// Everything works fine
	return &user.User, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (user *User) StoreFile(filename string, data []byte) {
	///////////////////////////////////////
	//           INODE STRUCTURE         //
	///////////////////////////////////////

	// Generate Key to store the File Inode
	passbyte := []byte((*user).Password + filename)
	saltbyte := []byte((*user).Username + filename)

	// key = Argon2Key(password + filename, username + filename, 10)
	keyHash := userlib.Argon2Key(passbyte, saltbyte, 10)
	marsh, err := json.Marshal(keyHash)
	if err != nil {
		userlib.DebugMsg("Key Marshalling failed")
	}
	// This is the key where encrypted Inode struct for "filename" is stored
	fileKey := hex.EncodeToString(marsh)
	userlib.DebugMsg("fileKey " + fileKey)

	//
	// Initialize the Inode structure without any signature (at the moment)
	//

	// Generate a random Initialization Vector and random address for
	// encryption of SharingRecord Structure
	iv := make([]byte, userlib.BlockSize)
	copy(iv, userlib.RandomBytes(userlib.BlockSize))

	randbyte, _ := json.Marshal(userlib.RandomBytes(userlib.BlockSize))
	address := hex.EncodeToString(randbyte[:16])

	file := &Inode_r{
		KeyAddr: fileKey, // The key at which this struct will be stored
		Inode: Inode{
			Filename:     filename,
			ShRecordAddr: address,
			SymmKey:      randbyte[:16],
		},
	}

	// Store the signature of User_r.User in User_r.Signature
	fileMarsh, err := json.Marshal(file.Inode)
	if err != nil {
		userlib.DebugMsg("Inode_r.Inode Marshalling failed")
	}

	file.Signature, err = userlib.RSASign(user.Privkey, fileMarsh)
	if err != nil {
		userlib.DebugMsg("RSA Signing of Inode_r.Inode failed")
	}

	// Finally, encrypt the whole Inode_r struct with User's Public key
	inodeMarsh, err := json.Marshal(file)
	if err != nil {
		userlib.DebugMsg("Inode_r Marshalling failed")
	}

	// To store encrypted chunks
	var encrypted [][]byte
	var encryptedBlock []byte
	index := 0

	for index < len(inodeMarsh) {
		// RSA Asymmetric Key Encryption
		encryptedBlock, err = userlib.RSAEncrypt(&user.Privkey.PublicKey,
			inodeMarsh[index:index+190], []byte("Tag"))
		if err != nil {
			userlib.DebugMsg("RSA Encryption of Inode_r failed\n")
		}
		index += 190
		encrypted = append(encrypted, encryptedBlock)
	}

	encryptedMarsh, err := json.Marshal(encrypted)
	if err != nil {
		userlib.DebugMsg("Marshalling of encrypted blocks failed")
	}

	// TODO: Optimize this at the end via channels
	userlib.DatastoreDelete(fileKey)
	userlib.DatastoreSet(fileKey, encryptedMarsh)

	//
	///////////////////////////////////////
	//      SHARINGRECORD STRUCTURE      //
	///////////////////////////////////////

	var addr []string
	var keys [][]byte

	// Generate a random Initialization Vector and random address for
	// encryption of SharingRecord Structure

	randbyte, _ = json.Marshal(userlib.RandomBytes(userlib.BlockSize))
	address = hex.EncodeToString(randbyte[:16])

	// Here, we append the first block of data to the list of blocks
	// The address and the encryption key for the block
	addr = append(addr, address)
	keys = append(keys, randbyte[:16])

	shrecord := &SharingRecord_r{
		KeyAddr: file.Inode.ShRecordAddr, // The key at which this struct will be stored
		SharingRecord: SharingRecord{
			Type:       "Sharing Record",
			MainAuthor: user.Username,
			Address:    addr,
			SymmKey:    keys,
		},
	}

	// HMAC Signature via symmetric keys
	// Store the signature of SharingRecord_r.SharingRecord in Signature
	shrMarsh, err := json.Marshal(shrecord.SharingRecord)
	if err != nil {
		userlib.DebugMsg("SharingRecord_r.SharingRecord Marshalling failed")
	}
	mac := userlib.NewHMAC(file.Inode.SymmKey)
	mac.Write(shrMarsh)
	shrecord.Signature = mac.Sum(nil)

	// Finally, encrypt the whole SharingRecord_r structure
	shrecord_rMarsh, err := json.Marshal(shrecord)
	if err != nil {
		userlib.DebugMsg("SharingRecord_r Marshalling failed")
	}

	ciphertext := make([]byte, userlib.BlockSize+len(shrecord_rMarsh))
	iv = ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))

	// NOTE: The "key" needs to be of 16 bytes
	cipher := userlib.CFBEncrypter(file.Inode.SymmKey, iv) // Check [:16]
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(shrecord_rMarsh))
	// userlib.DebugMsg("Message  ", hex.EncodeToString(ciphertext))

	// Push the AES-CFB Encrypted SharingRecord structure to Data Store
	userlib.DatastoreDelete(file.Inode.ShRecordAddr)
	userlib.DatastoreSet(file.Inode.ShRecordAddr, ciphertext)

	//
	///////////////////////////////////////
	//           DATA STRUCTURE          //
	///////////////////////////////////////
	dbkey := shrecord.SharingRecord.SymmKey[0]

	// HMAC Signature of data block via symmetric key
	mac = userlib.NewHMAC(dbkey)
	mac.Write(data)

	dblock := &Data{
		// The key at which this struct will be stored
		KeyAddr:   shrecord.SharingRecord.Address[0],
		Value:     data,
		Signature: mac.Sum(nil),
	}

	// Finally, encrypt the whole data block using Symmetric Key
	dblockMarsh, err := json.Marshal(dblock)
	if err != nil {
		userlib.DebugMsg("Data block Marshalling failed")
	}

	cipherdata := make([]byte, userlib.BlockSize+len(dblockMarsh))
	iv = cipherdata[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))

	// NOTE: The "key" needs to be of 16 bytes
	cipher = userlib.CFBEncrypter(dbkey, iv) // Check [:16]
	cipher.XORKeyStream(cipherdata[userlib.BlockSize:], []byte(dblockMarsh))

	// Push the AES-CFB Encrypted data block structure to Data Store
	userlib.DatastoreDelete(shrecord.SharingRecord.Address[0])
	userlib.DatastoreSet(shrecord.SharingRecord.Address[0], cipherdata)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about hat the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
