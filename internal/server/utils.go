package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/code"
)

func randomString(length int) (string, error) {
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

	s := ""
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))-1))
		if err != nil {
			return "", err
		}
		s += string(letters[n.Int64()])
	}
	return s, nil
}

func render(ctx echo.Context, code int, name string, data map[string]any) error {
	csrfToken, ok := ctx.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
	if !ok {
		return errors.New("failed to get csrf token from context")
	}
	data["CSRFToken"] = csrfToken
	return ctx.Render(code, name, data)
}

func excludeInvalidScopes(scopes, validScopes []string) []string {
	return slices.DeleteFunc(scopes, func(scope string) bool {
		return !slices.Contains(validScopes, scope)
	})
}

func sha512String(v string) string {
	vv := sha512.Sum512([]byte(v))
	return hex.EncodeToString(vv[:])
}
func createCode(ctx context.Context, db *ent.Client, userID uuid.UUID, groupIDs []uuid.UUID, clientID, scope, codeChallenge string) (*ent.Code, string, error) {
	for {
		c, err := randomString(40)
		if err != nil {
			return nil, "", err
		}
		hashedCode := sha512String(c)
		if exists, err := db.Code.Query().
			Where(code.Code(hashedCode)).
			Exist(ctx); err != nil {
			return nil, "", err
		} else if exists {
			continue
		}

		cc, err := db.Code.Create().
			AddGroupIDs(groupIDs...).
			SetUserID(userID).
			SetCode(hashedCode).
			SetExpiresAt(time.Now().Add(time.Minute)).
			SetClientID(clientID).
			SetScope(scope).
			SetCodeChallenge(codeChallenge).
			Save(ctx)
		if err != nil {
			return nil, "", err
		}
		return cc, c, nil
	}
}

func getBasicUserPassword(header http.Header) (username, password string, err error) {
	authz := header.Get("Authorization")
	log.Println(authz)
	left, right, ok := strings.Cut(authz, " ")
	if !ok {
		return "", "", errors.New("invalid authorization type")
	}
	if strings.ToLower(left) != "basic" {
		return "", "", errors.New("not basic")
	}

	decoded, err := base64.StdEncoding.DecodeString(right)
	if err != nil {
		return "", "", err
	}

	u, p, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", errors.New("invalid username:password")
	}
	username, err = url.QueryUnescape(u)
	if err != nil {
		return "", "", err
	}
	password, err = url.QueryUnescape(p)
	if err != nil {
		return "", "", err
	}
	return username, password, nil
}

func getBearerToken(header http.Header) (string, error) {
	authz := header.Get("Authorization")
	left, right, ok := strings.Cut(authz, " ")
	if !ok {
		return "", errors.New("invalid authroization")
	}

	if strings.ToLower(left) != "bearer" {
		return "", errors.New("invalid authorization type")
	}

	return right, nil
}

func createAccessToken(ctx context.Context, db *ent.Client, userID uuid.UUID, groupIDs []uuid.UUID) (*ent.AccessToken, string, error) {
	for {
		t, err := randomString(20)
		if err != nil {
			return nil, "", err
		}

		hashed := sha512String(t)
		if exists, err := db.AccessToken.Query().
			Where(accesstoken.Token(hashed)).
			Exist(ctx); err != nil {
			return nil, "", err
		} else if exists {
			continue
		}

		tt, err := db.AccessToken.Create().
			SetToken(hashed).
			SetExpiresAt(time.Now().Add(time.Hour)).
			SetUserID(userID).
			AddGroupIDs(groupIDs...).
			Save(ctx)
		if err != nil {
			return nil, "", err
		}
		return tt, t, nil
	}
}

func slicesMap[T, E any](s []T, f func(v T) E) []E {
	r := make([]E, 0, len(s))
	for _, v := range s {
		r = append(r, f(v))
	}
	return r
}

func getAuthUser(ctx echo.Context, db *ent.Client) (*ent.User, error) {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return nil, err
	}

	userID, ok := sess.Values["user_id"].(string)
	if !ok {
		return nil, echo.ErrUnauthorized
	}

	user, err := db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, echo.ErrUnauthorized
		}
		return nil, err
	}
	return user, nil
}

func validateRedirectURI(redirectURI string, validURIs []string) (*url.URL, error) {
	if len(validURIs) == 0 {
		if redirectURI == "" {
			return nil, errors.New("empty redirect_uri")
		}
		return url.Parse(redirectURI)
	}

	if len(validURIs) == 1 {
		if redirectURI == "" {
			return url.Parse(validURIs[0])
		}
	}

	if slices.ContainsFunc(validURIs, func(u string) bool {
		return strings.HasPrefix(redirectURI, u)
	}) {
		return url.Parse(redirectURI)
	}
	return nil, errors.New("mismatch redirect_uri")
}

func authorizeErrorRedirect(ctx echo.Context, uri *url.URL, errorCode, state string) error {
	q := uri.Query()
	q.Set("error", errorCode)
	q.Set("state", state)
	uri.RawQuery = q.Encode()
	return ctx.Redirect(http.StatusFound, uri.String())
}

func hmacSign(v any, secret string) (string, error) {
	message, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(message); err != nil {
		return "", err
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

func hmacVerify(sig string, v any, secret string) error {
	sig2, err := hmacSign(v, secret)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(sig), []byte(sig2)) == 0 {
		return errors.New("invalid signature")
	}
	return nil
}
