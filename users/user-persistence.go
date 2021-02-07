package users

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
)

var mutexForUsersFile sync.Mutex

var Users = map[string]string{
	"user1": "$2a$04$RPZE/QIYIPPMs5LdQLnvEusceMYVPdi8jLwT3xQjE1W/5bkHQRYYa",//password1
	"user2": "$2a$04$F.NebGTA/K3EnHBejFSFoe8QfCt.h8zFQamp560qbbjRNaLo.NwSO",//password2
}

func SaveUser(username string, hashedPassword string) {
	mutexForUsersFile.Lock()
	defer mutexForUsersFile.Unlock()

	// Open file using READ & WRITE permission.
	var file, err = os.OpenFile("./usersDB", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open users file")
		return
	}
	_, err = file.WriteString(username+":"+hashedPassword+"\n")
	if  err != nil {
		log.Println("Failed to write users file")
		return
	}

	// Save file changes.
	err = file.Sync()
	if  err != nil {
		log.Println("Failed to close users file")
		return
	}

	defer file.Close()
}

func LoadUsersFromDB() {
	// Open file for reading.
	var file, err = os.OpenFile("./usersDB", os.O_RDWR, 0644)
	if err != nil {
		log.Println("Failed to open users file")
		return
	}
	defer file.Close()

	// Read file, line by line
	scanner := bufio.NewScanner(file)
	var userPass []string
	for scanner.Scan() {
		userPass =strings.Split(scanner.Text(),":")
		Users[userPass[0]] = userPass[1]
	}
}