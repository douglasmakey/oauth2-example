# Oauth2-example with Go
Authentication is the most common part in any application. You can implement your own authentication system or use one of the many alternatives that exist, but in this case we are going to use OAuth2.

OAuth is a specification that allows users to delegate access to their data without sharing
their username and password with that service, if you want to read more about Oauth2 go [here](https://oauth.net/2/).
 
 
## Config Google Project
First things first, we need to create our Google Project and create OAuth2 credentials.

* Go to Google Cloud Platform
* Create a new project or select one if you already have it.
* Go to Credentials and then create a new one choosing  “OAuth client ID”
* Add "authorized redirect URL", for this example `localhost:8000/auth/google/callback`
* Copy the client_id and client secret


## How OAuth2 works with Google
The authorization sequence begins when your application redirects the browser to a Google URL; the URL includes query parameters that indicate the type of access being requested. Google handles the user authentication, session selection, and user consent. The result is an authorization code, which the application can exchange for an access token and a refresh token.

The application should store the refresh token for future use and use the access token to access a Google API. Once the access token expires, the application uses the refresh token to obtain a new one.

![Oauth2Google](https://developers.google.com/accounts/images/webflow.png)

## Let's go to the code
We will use the package "golang.org/x/oauth2" that provides support for making OAuth2 authorized and authenticated HTTP requests.

Create a new project(folder) in your workdir in my case I will call it 'oauth2-example', and we need to include the package of oauth2.

`go get golang.org/x/oauth2`


So into the project we create a main.go.

```go
package main

import (
	"fmt"
	"net/http"
	"log"
	"github.com/douglasmakey/oauth2-example/handlers"
)

func main() {
	server := &http.Server{
		Addr: fmt.Sprintf(":8000"),
		Handler: handlers.New(),
	}

	log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("%v", err)
	} else {
		log.Println("Server closed!")
	}
}

```
We create a simple server using http.Server and run.

Next, we create folder 'handlers' that contains handler of our application, in this folder create 'base.go'.

```go
package handlers

import (
	"net/http"
)

func New() http.Handler {
	mux := http.NewServeMux()
	// Root
	mux.Handle("/",  http.FileServer(http.Dir("templates/")))

	// OauthGoogle
	mux.HandleFunc("/auth/google/login", oauthGoogleLogin)
	mux.HandleFunc("/auth/google/callback", oauthGoogleCallback)

	return mux
}
```

We use **http.ServeMux** to handle our endpoints, next we create the Root endpoint "/" for serving a simple template with a minimmum HTML&CSS in this example we use 'http. http.FileServer', that template is 'index.html' and is in the folder 'templates'.

Also we create two endpoints for Oauth with Google "/auth/google/login" and "/auth/google/callback". Remember when we configured our application in the Google console? The callback url must be the same.

Next, we create another file into handlers, we'll call it 'oauth_google.go', this file contains all logic to handle OAuth with Google in our application.

We Declare the var googleOauthConfig with auth.Config to communicate with Google.
Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an
access token.

```go
var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8000/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}
```


### Handler oauthGoogleLogin

This handler creates a login link and redirects the user to it:


AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must
always provide a non-empty string and validate that it matches with the state query parameter on your redirect callback, It's advisable that this is randomly generated for each request, that's why we use a simple cookie.
	
```go
func oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
	
```

### Handler oauthGoogleCallback

This handler check if the state is equals to oauthStateCookie, and pass the code to the function **getUserDataFromGoogle**.

```go
func oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	fmt.Fprintf(w, "UserInfo: %s\n", data)
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.
	
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}


```

### Full code oauth_google.go

```go
package handlers

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"fmt"
	"io/ioutil"
	"context"
	"log"
	"encoding/base64"
	"crypto/rand"
	"os"
	"time"
)

// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8000/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	/*
	AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
	validate that it matches the the state query parameter on your redirect callback.
	*/
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	fmt.Fprintf(w, "UserInfo: %s\n", data)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

```
## let's run and test
```bash
go run main.go
```
