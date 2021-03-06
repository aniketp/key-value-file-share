package assn1

import (
	"reflect"
	"testing"

	"github.com/fenilfadadu/cs628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Log("Loaded info:", string(v))

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}

func TestUserCorrupt(t *testing.T) {
	// InitUser
	user1, err := InitUser("aniket", "password1")
	if err != nil {
		t.Error(err.Error())
	}

	user2, err := InitUser("ashish", "password2")
	if err != nil {
		t.Error(err.Error())
	}

	t.Log(user1, user2)

	// GetUser (Try to ruin user data)
	aniketKey := GetUserKey("aniket", "password1")
	aniketCnt, _ := GetMapContent(aniketKey)
	// fmt.Println(aniketCnt)
	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
	SetMapContent(aniketKey, aniketCnt)

	// Here, we intentionally want the unmarshalling to fail
	user1, err = GetUser("aniket", "password1")
	if err != nil {
		t.Log(err.Error())
	} else {
		t.Error(user1)
	}
}

func TestStoreFile(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}

	t.Log("File received: ", string(v2))

}

func TestShareMutate(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload bob", err2)
	}

	// Bob's version of sharedfile
	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}

	t.Log("The content of file is : ", string(v2))

	// Bob rewrites the shared-file
	newCont := []byte("This is NEW content")
	u2.StoreFile("file2", newCont)
	// Alice loads the same file (expect the test to currently fail)
	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error(err.Error())
	}

	if string(newCont) != string(v1) {
		t.Error("The file contents don't match")
	}

	t.Log("The contents match: ", string(newCont))
}

func TestRevokeTransitive(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload bob", err2)
	}

	u3, err := InitUser("charles", "fuobar")
	if err != nil {
		t.Error("Failed to initialize charles", err)
	}

	u1.StoreFile("file11", []byte("This belongs to Alice"))
	sharing, err := u1.ShareFile("file11", "bob")
	if err != nil {
		t.Error("Sharing with bob failed")
	}

	err = u2.ReceiveFile("file12", "charles", sharing)
	if err != nil {
		t.Log("Sharing with wrong user failed as expected, ", err.Error())
	}

	u2.ReceiveFile("file12", "alice", sharing)
	u2.AppendFile("file12", []byte("\nThis belongs to Bob"))
	sharing2, err := u2.ShareFile("file12", "charles")
	if err != nil {
		t.Error("Sharing with charles failed")
	}

	u3.ReceiveFile("file13", "bob", sharing2)
	u3.AppendFile("file13", []byte("\nThis belongs to Charles"))

	apple, _ := u1.LoadFile("file11")
	t.Log(string(apple))

	// Bob revokes all other access
	err = u2.RevokeFile("file13")
	t.Log("Can't revoke other's file ", err.Error())
	err = u2.RevokeFile("file12")
	if err != nil {
		t.Error("Bob couldn't revoke his own file, ", err.Error())
	}

	_, err1 := u1.LoadFile("file11")
	_, err2 = u3.LoadFile("file13")
	if err1 == nil || err2 == nil {
		t.Error("Alice and Charles bypassed revoke call by bob")
	}

	apple, err = u2.LoadFile("file12")
	t.Log(string(apple), err)

	// t.Log(err1, err2)

}
