package gookauth

import (
	"bytes"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

type MockClient struct {
	Response *http.Response
}

func (c *MockClient) Get(url string) (res *http.Response, err error) {
	err = nil
	if c.Response == nil {
		err = http.ErrShortBody
	}
	return c.Response, err
}

func TestClient(t *testing.T) {
	client := Client{"APP_ID", "APP_SECRET", "APP_SERVER_KEY", "REDIRECT_URI", "PERMISSIONS"}
	Convey("TestUrl", t, func() {
		url := client.DialogURL()
		should := "https://connect.mail.ru/oauth/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&scope=PERMISSIONS"
		So(url.String(), ShouldEqual, should)
	})

	Convey("Test getName", t, func() {
		res := &http.Response{}
		body := `[{
    "uid": "15410773191172635989",
    "first_name": "Евгений",
    "last_name": "Маслов",
    "nick": "maslov",
    "email": "emaslov@mail.ru",
    "sex": 0,
    "birthday": "15.02.1980", 
    "has_pic": 1,
    "pic": "http://avt.appsmail.ru/mail/emaslov/_avatar"
   }
]
		`
		res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
		httpClient = &MockClient{res}
		user, err := client.GetUser("1")
		So(err, ShouldBeNil)
		So(user.Name, ShouldEqual, "Евгений Маслов")

		Convey("Multiple response", func() {
			body := `[{
					    "uid": "15410773191172635989",
					    "first_name": "Евгений",
					    "last_name": "Маслов",
					    "nick": "maslov",
					    "email": "emaslov@mail.ru",
					    "sex": 0,
					    "birthday": "15.02.1980", 
					    "has_pic": 1,
					    "pic": "http://avt.appsmail.ru/mail/emaslov/_avatar"
					   },
					   {"uid": "15410773191172635989",
					    "first_name": "Евгений",
					    "last_name": "Маслов",
					    "nick": "maslov",
					    "email": "emaslov@mail.ru",
					    "sex": 0,
					    "birthday": "15.02.1980", 
					    "has_pic": 1,
					    "pic": "http://avt.appsmail.ru/mail/emaslov/_avatar"
					   }
					]`
			res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
			_, err := client.GetUser("6492")
			So(err, ShouldEqual, ErrorBadResponse)
		})

		Convey("Http error", func() {
			httpClient = &MockClient{nil}
			_, err := client.GetUser("6492")
			So(err, ShouldNotBeNil)
		})

		Convey("Server error", func() {
			body := `{"response": {"error": "500"}}`
			res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
			_, err := client.GetUser("6492")
			So(err, ShouldNotBeNil)
		})

	})

	Convey("Test sign", t, func() {
		client.SecretKey = "3dad9cbf9baaa0360c0f2ba372d25716"
		params := url.Values{}
		params.Add(methodParameter, "friends.get")
		params.Add("app_id", "423004")
		params.Add("session_key", "be6ef89965d58e56dec21acb9b62bdaa")
		params.Add("secure", "1")
		So(client.signServer(params), ShouldEqual, "4a05af66f80da18b308fa7e536912bae")
	})

	Convey("Test accessTokenUrl", t, func() {
		Convey("Request url ok", func() {
			urlStr := "https://connect.mail.ru/access_token?client_id=APP_ID&client_secret=APP_SECRET&code=CODE&grant_type=authorization_code&redirect_uri=REDIRECT_URI"
			url := client.accessTokenURL("CODE")
			So(url.String(), ShouldEqual, urlStr)
		})

		urlStr := "http://REDIRECT_URI?code=7a6fa4dff77a228eeda56603b8f53806c883f011c40b72630bb50df056f6479e52a"
		req, _ := http.NewRequest("GET", urlStr, nil)

		resTok := &http.Response{}
		body := `{"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3", "expires_in":43200, "x_mailru_vid":"6492"}`
		resTok.Body = ioutil.NopCloser(bytes.NewBufferString(body))
		httpClient = &MockClient{resTok}

		tok, err := client.GetAccessToken(req)
		So(err, ShouldBeNil)
		So(tok.AccessToken, ShouldEqual, "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3")
		So(tok.Expires, ShouldEqual, 43200)
		So(tok.UserID, ShouldEqual, "6492")

		Convey("Bad response", func() {
			resTok.Body = ioutil.NopCloser(bytes.NewBufferString("asdfasdf"))
			httpClient = &MockClient{resTok}
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})

		Convey("Bad url", func() {
			req, _ = http.NewRequest("GET", "http://REDIRECT_URI?error=kek", nil)
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})

		Convey("Http error", func() {
			httpClient = &MockClient{nil}
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})
	})
}
