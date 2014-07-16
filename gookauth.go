package gookauth

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

const (
	host                  = "connect.mail.ru"
	apiHost               = "www.appsmail.ru"
	apiUrl                = "platform/api"
	scheme                = "https"
	accessTokenAction     = "access_token"
	appIDParameter        = "client_id"
	appSecretParameter    = "client_secret"
	methodParameter       = "method"
	sigParameter          = "sig"
	responseTypeParameter = "response_type"
	responseTypeCode      = "code"
	redirectParameter     = "redirect_uri"
	grantTypeParameter    = "grant_type"
	grantType             = "authorization_code"
	scopeParameter        = "scope"
	authAction            = "oauth/authorize"
	codeParameter         = "code"
	usersGetAction        = "users.get"
	uidsParameter         = "uids"
)

var (
	// ErrorBadCode occures when server returns blank code or error
	ErrorBadCode = errors.New("bad code")
	// ErrorBadResponse occures when server returns unexpected response
	ErrorBadResponse                = errors.New("bad server response")
	httpClient       mockHTTPClient = &http.Client{}
)

// Client for vkontakte oauth
type Client struct {
	ID          string
	Secret      string
	SecretKey   string
	RedirectURL string
	Scope       string
}

type User struct {
	ID        string `json:"uid"`
	Photo     string `json:"pic"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Name      string
}

// AccessToken describes oath server response
type AccessToken struct {
	AccessToken string `json:"access_token"`
	Expires     int    `json:"expires_in"`
	UserID      string `json:"x_mailru_vid"`
}

type mockHTTPClient interface {
	Get(url string) (res *http.Response, err error)
}

func (client *Client) base(action string) url.URL {
	u := url.URL{}
	u.Host = host
	u.Scheme = scheme
	u.Path = action

	query := u.Query()
	query.Add(appIDParameter, client.ID)
	query.Add(redirectParameter, client.RedirectURL)

	u.RawQuery = query.Encode()
	return u
}

// DialogURL is url for vk auth dialog
func (client *Client) DialogURL() url.URL {
	u := client.base(authAction)

	query := u.Query()
	query.Add(scopeParameter, client.Scope)
	query.Add(responseTypeParameter, responseTypeCode)

	u.RawQuery = query.Encode()
	return u
}

func (client *Client) accessTokenURL(code string) url.URL {
	u := client.base(accessTokenAction)

	query := u.Query()
	query.Add(appSecretParameter, client.Secret)
	query.Add(codeParameter, code)
	query.Add(grantTypeParameter, grantType)

	u.RawQuery = query.Encode()
	return u
}

// GetAccessToken is handler for redirect, gets and returns access token
func (client *Client) GetAccessToken(req *http.Request) (token *AccessToken, err error) {
	query := req.URL.Query()
	code := query.Get(codeParameter)
	if code == "" {
		err = ErrorBadCode
		return nil, err
	}

	requestURL := client.accessTokenURL(code)
	res, err := httpClient.Get(requestURL.String())
	if err != nil {
		return nil, err
	}

	token = &AccessToken{}
	decoder := json.NewDecoder(res.Body)
	return token, decoder.Decode(token)
}

func (client *Client) signServer(params url.Values) (hash string) {
	var buffer bytes.Buffer
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appendix := fmt.Sprintf("%s=%s", key, params.Get(key))
		buffer.WriteString(appendix)
	}
	buffer.WriteString(client.SecretKey)
	h := md5.New()
	h.Write(buffer.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (client *Client) GetUser(uid string) (user User, err error) {
	u := client.base("")
	u.Host = apiHost

	q := u.Query()
	q.Del(appIDParameter)
	q.Del(redirectParameter)
	q.Add(methodParameter, usersGetAction)
	q.Add(uidsParameter, fmt.Sprint(uid))
	q.Add(sigParameter, client.signServer(q))

	u.RawQuery = q.Encode()
	res, err := httpClient.Get(u.String())
	if err != nil {
		return
	}
	answer := []User{}
	decoder := json.NewDecoder(res.Body)
	if err = decoder.Decode(&answer); err != nil {
		return
	}
	if len(answer) != 1 {
		err = ErrorBadResponse
		return
	}
	user = answer[0]
	user.Name = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	return
}
