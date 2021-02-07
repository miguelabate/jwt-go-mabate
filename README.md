# JWT Go example
Code based on [here](https://github.com/sohamkamani/jwt-go-example).

Adding some changes:
- Using Bearer token header instead of cookies
- User management signup with persistence on disk (simple file)
- User log out feature using jwtToken white listing.
- Hash the passwords stored locally

```sh
go build
./jwt-go-mabate
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

