package main

import (
	"fmt"
	"github.com/devfacet/gocmd"
	"github.com/miguelabate/jwt-go-mabate/jwthandler"
	"github.com/miguelabate/jwt-go-mabate/users"
	"log"
	"net/http"
)

func main() {
	flags := struct {
		Help      bool `short:"h" long:"help" description:"Display usage" global:"true"`
		Version   bool `short:"v" long:"version" description:"Display version"`
		VersionEx bool `long:"vv" description:"Display version (extended)"`
		Start     struct {
			Cors bool `short:"c" long:"cors" required:"false" default:"true" description:"Enable cors"`
			Port int  `short:"p" long:"port" required:"false" default:"8000" description:"Port where the service will serve"`
		} `command:"start" description:"Starts jwt service"`
		AddUser struct {
			Username string   `short:"u" long:"name" required:"true" description:"Username"`
			Password string   `short:"p" long:"password" required:"true" description:"Password for the user"`
			Roles    []string `short:"r" long:"roles" required:"true" description:"Roles"`
		} `command:"adduser" description:"creates a new user with roles"`
	}{}

	// Start service
	gocmd.HandleFlag("Start", func(cmd *gocmd.Cmd, args []string) error {
		InitService(flags.Start.Cors, flags.Start.Port)
		return nil
	})

	// Start service
	gocmd.HandleFlag("AddUser", func(cmd *gocmd.Cmd, args []string) error {
		users.LoadUsersFromDB()
		users.AddUserWithNotHashedPassAndPersist(flags.AddUser.Username, flags.AddUser.Password, flags.AddUser.Roles)
		return nil
	})

	// Init the app
	gocmd.New(gocmd.Options{
		Name:        "Jwt Go Server",
		Version:     "1.0.0",
		Description: "Standalone jwt token auth server",
		Flags:       &flags,
		ConfigType:  gocmd.ConfigTypeAuto,
	})
}

func InitService(enableCors bool, servingPort int) {

	fmt.Println("Starting JWT Auth Go server ...")
	// provided
	http.HandleFunc("/signin", jwthandler.SignIn)
	http.HandleFunc("/signup", jwthandler.SignUp)
	http.HandleFunc("/refresh", jwthandler.Refresh)
	http.HandleFunc("/logout", jwthandler.Logout)

	// custom
	http.HandleFunc("/welcome", jwthandler.WithJwtCheck(Welcome, []string{"CLIENT", "ADMIN"}, enableCors))

	// can override some config values
	//users.PersistenceUsersFileLocation = "altUserDB"
	//jwthandler.JwtTokenLifeInMinutes = 10
	//jwthandler.JwtTokenRefreshPeriodInSeconds = 60
	jwthandler.GlobalCorsEnabled = enableCors

	users.LoadUsersFromDB()

	//// start the server on port 8000
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", servingPort), nil))

}

/**
* An example endpoint showing roles and auth
 */
func Welcome(w http.ResponseWriter, r *http.Request, jwtToken *jwthandler.MaJwt) {
	// username given in the token
	w.Write([]byte(fmt.Sprintf("Welcome %s!\n Your roles are: %s", jwtToken.Claims.Username, jwtToken.Claims.Roles)))
}
