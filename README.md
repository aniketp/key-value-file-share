# key-value-file-share
An implementation of a secure and scalable key-value file-share platform on an untrusted server. The design maintains confidentiality and integrity of files with relevant encryption and verification techniques, while simultaneously maintaining efficiency in load-store operations.

Made as a part of the assignment for the course Computer Systems Security (CS628). The base infrastructure and server APIs were provided in problem statement.

### Key features
* Transitive collaboration amongst users with the assumption that one or more of them may be adversarial.
* Protection against Man in the Middle attack while sharing a secret token through an insecure channel.   

**Note:** The design does not take into account the possibility of Denial of Service attacks or Rollback attacks. In short, availability is not to be secured.

<hr>

#### Group Members

| __Name__ | __Email__ |
|-------------|------------|
| Aniket Pandey | [aniketp@iitk.ac.in](mailto:aniketp@iitk.ac.in) |
| Ashish Kumar | [akashish@iitk.ac.in](mailto:akashish@iitk.ac.in) |

#### Usage and Testing
 * **Frontline** `go run main.go`
 * **Test-cases** `go test -v`

Alternate implementation following the similar design: [aasis21/encrypted_dropbox_](https://github.com/aasis21/encrypted_dropbox_)
