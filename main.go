package main

import (
	"fmt"

	"github.com/aasis21/encrypted_dropbox/assn1"
	"github.com/google/uuid"
)

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// All the structs to be used in the assignment

func main() {
	a := &assn1.User_r{
		KeyAddr:   "apple",
		Signature: []byte("apple"),
		User: assn1.User{
			Username: "xxx",
			Password: "apple",
		},
	}
	fmt.Printf("%#v\n", a.KeyAddr)

	assn1.InitUser("apple", "mangoa")
	assn1.InitUser("cake", "mangoa")
	user, err := assn1.GetUser("apple", "mangoa")
	if err != nil {
		fmt.Println(err)
	}

	user.StoreFile("mango", []byte("apple"))
	err = user.AppendFile("mango", []byte("mango"))
	err = user.AppendFile("mango", []byte("banana"))
	// data, err := user.LoadFile("mango")
	// fmt.Println(string(data))

	sharing, err := user.ShareFile("mango", "cake")
	// fmt.Println(sharing, err)

	cakeUser, err := assn1.GetUser("cake", "mangoa")
	if err != nil {
		fmt.Println(err)
	}

	cakeUser.ReceiveFile("banana", "apple", sharing)
	cakeUser.AppendFile("banana", []byte("cakcesfile"))
	data, err := user.LoadFile("mango")
	fmt.Println(string(data))

	_ = user.RevokeFile("mango")
	err = cakeUser.AppendFile("banana", []byte("maliciousFile"))
	fmt.Println(err)

	// applae := [][]byte{[]byte("Mango"), []byte("sadas")}
	// app := make([]byte, len(applae)-2)

	// app = append(app, applae[0]...)
	// app = append(app, applae[1]...)
	// fmt.Println(applae[0], applae[1], app)

	// f := uuid.New()

	// // fmt.Println(userlib.NewHMAC([]byte("random-password")))

	// // Marshalling and Unmarshalling of the structures worked, cool

	// // h := hex.EncodeToString([]byte("fubar"))
	// d, _ := json.Marshal(f)
	// var g uuid.UUID
	// json.Unmarshal(d, &g)

	// // g = bytesToUUID([])

	// // Debug println's
	// fmt.Printf("Creation of a new error %s\n",
	// 	errors.New(strings.ToTitle("This is an error")))

	// var key *userlib.PrivateKey
	// key, _ = userlib.GenerateRSAKey()
	// // pubkey := key.PublicKey // Public key, corresponding to a private key

	// msg := []byte("Apple mango")
	// // msg1 := []byte("Apple banana")
	// // hash := userlib.NewSHA256()
	// // fmt.Println(bytesToUUID(msg1))

	// sir := "asedas"
	// filename := []byte("akashish-user" + sir)
	// hash := userlib.Argon2Key(filename, []byte("ghanshyam-ssap"), 3)
	// marsh, err := json.Marshal(hash)
	// if err != nil {
	// 	userlib.DebugMsg("Marshal failed")
	// }

	// marsh_string := hex.EncodeToString(marsh)
	// fmt.Println(marsh_string)
	// marsh_1, err := hex.DecodeString(marsh_string)
	// if err != nil {
	// 	userlib.DebugMsg("Decoding Failed")
	// }

	// var hash1 []byte
	// err = json.Unmarshal(marsh_1, &hash1)
	// if err != nil {
	// 	userlib.DebugMsg("Unmarshalling Failed")
	// }

	// fmt.Printf("Initial hash %v\nFinal hash %v\n", hash, hash1)

	// fmt.Println(marsh_string, len(marsh_string))

	// // Can use json.Marshal to turn hash.Hash object to string
	// // json.Marshal() -> hex.EncodeToString()

	// userlib.DebugMsg("Mango %v", hash)

	// apple, _ := userlib.RSASign(key, msg)
	// err = userlib.RSAVerify(&key.PublicKey, msg, apple)
	// if err != nil {
	// 	fmt.Println("Signature matched")
	// }

	// fmt.Println(apple)
	// // fmt.Println(key, "\n", pubkey)
	// fmt.Printf("Key is %v\n%v", key, pubkey)
}
