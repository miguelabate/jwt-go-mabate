package users

import (
	"bufio"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
	"sync"
)

var PersistenceUsersFileLocation = "./usersDB"

var mutexForUsersFile sync.Mutex

// example of a map entry: "user1": "$2a$04$RPZE/QIYIPPMs5LdQLnvEusceMYVPdi8jLwT3xQjE1W/5bkHQRYYa", //password1
var Users = map[string]string{}

// example of a map entry: "user1": ["ADMIN","CLIENT"]
var UserRoles = map[string][]string{}

// saves a newly created user with its roles and hashed pass to disk
func SaveUser(username string, hashedPassword string, roles []string) {
	mutexForUsersFile.Lock()
	defer mutexForUsersFile.Unlock()

	// Open file using READ & WRITE permission.
	var file, err = os.OpenFile(PersistenceUsersFileLocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open users file")
		return
	}
	_, err = file.WriteString(username + ":" + strings.Join(roles, ",") + ":" + hashedPassword + "\n")
	if err != nil {
		log.Println("Failed to write users file")
		return
	}

	// Save file changes.
	err = file.Sync()
	if err != nil {
		log.Println("Failed to close users file")
		return
	}

	defer file.Close()
}

// function called one time (at the startup of the service) to load all users and roles from teh file in disk
func LoadUsersFromDB() {
	// Open file for reading.
	var file, err = os.OpenFile(PersistenceUsersFileLocation, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Println("Failed to open users file")
		return
	}
	defer file.Close()

	// Read file, line by line
	scanner := bufio.NewScanner(file)
	var userRolesPass []string
	for scanner.Scan() {
		userRolesPass = strings.Split(scanner.Text(), ":")
		Users[userRolesPass[0]] = userRolesPass[2]
		UserRoles[userRolesPass[0]] = strings.Split(userRolesPass[1], ",")
	}
}

// used for testing, just adds a user and roles directly
func AddUserWithHashedPass(userName string, userPassHashed string, roles []string) {
	Users[userName] = userPassHashed
	UserRoles[userName] = roles
}

func AddUserWithNotHashedPassAndPersist(userName string, userPass string, roles []string) {
	Users[userName] = HashAndSaltPassword([]byte(userPass))
	UserRoles[userName] = roles

	//persist
	SaveUser(userName, Users[userName], roles)
}

func HashAndSaltPassword(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}
