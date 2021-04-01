# JWT Go

Implementation of a service exposing endpoints to signup, signin, logout, refresh and authenticate users using jwt tokens.

Features:
- Signup, SignIn, Logout and refresh token operations
- Using Bearer token header for jwt token
- User management signup with persistence on disk (simple file)
- User log out feature using jwtToken white listing.
- Hash the passwords stored locally
- Using github.com/lestrrat-go/jwx/jwt for jwt handling

This code is also showcased in [this article](https://miguelabate.com/jwt-token-auth-in-golang/) 

Initial base code credit to [here](https://github.com/sohamkamani/jwt-go-example).

#Notes
The server could be run as is for trial purposes but the idea 
is to extend it with the endpoints of your own service that require Auth.

This can be done wrapping your endpoint like this:
```
http.HandleFunc("/welcome", jwthandler.WithJwtCheck(Welcome, []string{"CLIENT", "ADMIN"}, enableCors))
```

And your endpoint is implemented like this:  

```
func Welcome(w http.ResponseWriter, r *http.Request, jwtToken *jwthandler.MaJwt) {
  // username given in the token
  w.Write([]byte(fmt.Sprintf("Welcome %s!\n Your roles are: %s", jwtToken.Claims.Username, jwtToken.Claims.Roles)))
}
```

more on this can be seen in the main.go file.

#Run server

```sh
go build -o jwt-go-server
./jwt-go-server start -p 8000
```

Sign up a new user:
```
curl -X POST -i -H "Accept: application/json" -H "Content-Type: application/json" --data '{"username":"newuser","password":"newpass"}' http://localhost:8000/signup

```

Sign in with the new user:
```
curl -X POST -i -H "Accept: application/json" -H "Content-Type: application/json" --data '{"username":"newuser","password":"newpass"}' http://localhost:8000/signin

```

Try some endpoint that enforces authentication (need to send jwt token)
```
curl -X GET -i -H "Authorization: Bearer <your-jwt-token>" http://localhost:8000/welcome
```

Try refresh endpoint to get a new token (need to send jwt token)
```
curl -X GET -i -H "Authorization: Bearer <your-jwt-token>" http://localhost:8000/refresh
```
Logout (need to send jwt token). It takes the passed token out of the whitelist, it cannot be used again (so it works as a logout)
```
curl -X GET -i -H "Authorization: Bearer <your-jwt-token>" http://localhost:8000/logout
```

#Add users

Adding a user  

```
./jwt-go-mabate adduser -u johnny -p johnnypass -r CLIENT -r ADMIN
```

#Show help

More detailed explanation of how to run the server

```
./jwt-go-mabate
Usage: Jwt Go Server [options...] COMMAND [options...]

Standalone jwt token auth server

Options:
  -h, --help            Display usage
  -v, --version         Display version
      --vv              Display version (extended)

Commands:
  start                 Starts jwt service
    -c, --cors          Enable cors (default true)
    -p, --port          Port where the service will serve (default 8000)
  adduser               creates a new user with roles
    -u, --name          Username
    -p, --password      Password for the user
    -r, --roles         Roles


```
