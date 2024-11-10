# github-teams-oauth2

github teams oauth2 wrapped github oauth2

```
http://localhost:8080/oauth2/authorize?client_id=test-client-id&state=123&response_type=code
```

```
CODE=
curl http://localhost:8080/oauth2/token \
    -d grant_type=authorization_code \
    -d code=$CODE \
    -d client_id=test-client-id
```

```
TOKEN=
curl http://localhost:8080/userinfo -H "Authorization: Bearer $TOKEN"
```

test client

```
go run test-client/main.go 8081
```
