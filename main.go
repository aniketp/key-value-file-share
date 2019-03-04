package main

import (
	"fmt"

	"github.com/aniketp/key-value-file-share/assn1"
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
	// InitUser
	user1, err := assn1.InitUser("aniket", "password1")
	if err != nil {
		fmt.Println(err.Error())
	}

	user2, err := assn1.InitUser("ashish", "password2")
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(user1, user2)

	// GetUser (Try to ruin user data)
	aniketKey := assn1.GetUserKey("aniket", "password1")
	aniketCnt, _ := assn1.GetMapContent(aniketKey)
	// fmt.Println(aniketCnt)
	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
	assn1.SetMapContent(aniketKey, aniketCnt)

	user1, err = assn1.GetUser("aniket", "password1")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(user1)
	}
}
