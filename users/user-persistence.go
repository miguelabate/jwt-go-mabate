package users

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
)

var UsersFileLocation = "./usersDB"

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
	var file, err = os.OpenFile(UsersFileLocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	var file, err = os.OpenFile(UsersFileLocation, os.O_RDWR|os.O_CREATE, 0644)
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
func AddUser(userName string, userPass string, roles []string) {
	Users[userName] = userPass
	UserRoles[userName] = roles
}
