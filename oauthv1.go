// This package was created in helping others with OAuth V1 & Quickbooks
// Currently it is only set to do url query parameters as that is how quickbooks takes it.
// Next projects are to use other methods or simply build the OAuth2 Library.

package oauthv1

import (

	// Tools for outputing to server terminal
	"fmt"

	// Tools for creating string outpus
	"strings"

	// HTTP Tools for Querying
	"net/http"
	"net/url"

	// Http Testing
	// "net/http/httputil"

	// Oauth_timestamp
	"strconv"
	"time"

	// Securing the Random Number Generator for NONCE
	"crypto/rand"

	// Packages for creating oauth signature
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"

// For Error Handling
//"errors"
)

// An OAuth Consumer Structure to hold all its information
type oauthConsumer struct {

	// Access Token
	Access_URL          string
	Access_Token        string
	Access_Token_Secret string

	// Authorization
	Authorize_URL string

	// Request Token
	Request_URL          string
	Request_Token        string
	Request_Token_Secret string

	// Consumer Information
	Callback         string
	Consumer_Key     string
	Consumer_Secret  string
	NOnce            string
	RealmId          string
	Signature        string
	SignatureKey     string
	Signature_Method string
	Timestamp        string
	Verifier         string
	Version          string
}

func NewConsumer(accessUrl string, authorizeURL string, requestURL string, callback string, consumerKey string, consumerSecret string) *oauthConsumer {
	// Intialize a new consumer
	consumer := &oauthConsumer{
		Access_URL:    accessUrl,
		Authorize_URL: authorizeURL,
		Request_URL:   requestURL,
		Callback:      callback,
		Consumer_Key:  consumerKey,
		// The & is crucial, once we have request token secret we will
		// append that to Signature Key after the &
		Consumer_Secret: consumerSecret,
		// For now these are defaults on how we built this library
		Signature_Method: "HMAC-SHA1",
		Version:          "1.0",
	}

	return consumer
}

func (consumer *oauthConsumer) CreateTimestamp() {
	// Set our timestamp in Minutes and format to String
	t := time.Now().Unix()
	consumer.Timestamp = strconv.FormatInt(t, 10)
}

func (consumer *oauthConsumer) CreateNOnce() {
	// Create a unique Nonce identifier
	// Base64 for letters and numbers.
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Println("NOnce Error: ", err)
	}
	// We need to escape the URL characters as well as base64 encode it as a string
	consumer.NOnce = url.QueryEscape(base64.StdEncoding.EncodeToString(nonce))
}

func (consumer *oauthConsumer) CreateSignature(uriMethod string, urlToken string) string {
	// Create OAuth Signature
	// Consists of 3 parts for String
	// 1. HTTP method
	// 2. Base URL Encoded with URL characters escaped
	// 3. OAuth Parameter string (Aplhabetized) Also URL Encoded with URL characters escaped
	// SignatureKey is either ConsumerKey& or ConsumerKey&RequestTokenSecret

	if urlToken == "access" {

		uri_method := uriMethod
		url_encoded := url.QueryEscape(consumer.Access_URL)

		// Create Query Paramters
		oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
		oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
		oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
		oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
		oauth_request_token := "oauth_token=" + consumer.Request_Token + "&"
		oauth_verifier := "oauth_verifier=" + consumer.Verifier + "&"
		oauth_version := "oauth_version=" + consumer.Version

		oauth_parameters := oauth_consumer_key + oauth_nonce + oauth_signature_method + oauth_timestamp + oauth_request_token + oauth_verifier + oauth_version
		oauth_parameters = url.QueryEscape(oauth_parameters)

		uri := uri_method + "&" + url_encoded + "&" + oauth_parameters

		// Modify Signature Key for Access Token now that we have Request Token Secret
		consumer.SignatureKey = consumer.Consumer_Secret + "&" + consumer.Request_Token_Secret

		return Sign(uri, consumer.SignatureKey)

	} else if urlToken == "request" {

		uri_method := uriMethod
		url_encoded := url.QueryEscape(consumer.Request_URL)

		// Create Query Parameter
		oauth_callback := "oauth_callback=" + url.QueryEscape(consumer.Callback) + "&"
		oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
		oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
		oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
		oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
		oauth_version := "oauth_version=" + consumer.Version

		oauth_parameters := oauth_callback + oauth_consumer_key + oauth_nonce + oauth_signature_method + oauth_timestamp + oauth_version
		oauth_parameters = url.QueryEscape(oauth_parameters)

		uri := uri_method + "&" + url_encoded + "&" + oauth_parameters

		// Modify Signature Key for Request Token with just &
		consumer.SignatureKey = consumer.Consumer_Secret + "&"

		return Sign(uri, consumer.SignatureKey)
	}

	// Ok it is an API URL if not Request or Access
	uri_method := uriMethod
	url_encoded := url.QueryEscape(urlToken)

	// Create Query Paramters
	oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
	oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
	oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
	oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
	oauth_token := "oauth_token=" + consumer.Access_Token + "&"
	oauth_version := "oauth_version=" + consumer.Version

	oauth_parameters := oauth_consumer_key + oauth_nonce + oauth_signature_method + oauth_timestamp + oauth_token + oauth_version
	oauth_parameters = url.QueryEscape(oauth_parameters)

	uri := uri_method + "&" + url_encoded + "&" + oauth_parameters

	// Modify Signature Key for Access Token now that we have Request Token Secret
	//consumer.SignatureKey = consumer.SignatureKey + consumer.Request_Token_Secret

	// Modify Signature Key for API Request with consumer key and access token secret
	consumer.SignatureKey = consumer.Consumer_Secret + "&" + consumer.Access_Token_Secret

	return Sign(uri, consumer.SignatureKey)
}

func (consumer *oauthConsumer) GetRequestToken() {
	// Set the NOnce and Timestamp for Request Signature and Token
	// If they change during Signing and Call it fucks it up
	// So I call them ahead of time to set them.
	// I will call them again for Access Token
	consumer.CreateNOnce()
	consumer.CreateTimestamp()

	// Create the OAuth Header
	oauth_callback := "oauth_callback=" + url.QueryEscape(consumer.Callback) + "&"
	oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
	oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
	oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
	oauth_signature := "oauth_signature=" + consumer.CreateSignature("GET", "request") + "&"
	oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
	oauth_version := "oauth_version=" + consumer.Version

	oauthHDR := oauth_callback + oauth_consumer_key + oauth_nonce + oauth_signature_method + oauth_signature + oauth_timestamp + oauth_version

	client := &http.Client{}

	// Make the Request

	request, err := http.NewRequest("GET", consumer.Request_URL+"?"+oauthHDR, nil)

	if err != nil {
		fmt.Println("Request Error: ", err)
		return
	}

	// Get the Reponse
	response, err := client.Do(request)
	if response.Status != "200 OK" {
		fmt.Println("Response Status: ", response.Status)
		var buf [512]byte
		reader := response.Body
		for {
			n, err := reader.Read(buf[0:])
			if err != nil {
				fmt.Println("Response Error:", err)
				return
			}
			fmt.Println("Response Body: ", string(buf[0:n]))
			return
		}
		fmt.Println("Response Status Code Error:", err)
		return
	}

	// Take the Response and Extract the Request Tokens
	var buf [512]byte
	reader := response.Body
	for {
		n, err := reader.Read(buf[0:])
		if err != nil {
			fmt.Println("Response Reader Error:", err)
			return
		}
		// Uncomment for Debugging
		// fmt.Println(string(buf[0:n]))

		// Breaking apart Response for the Request Token and Secret
		response_tokens := string(buf[0:n])
		response_tokens_array := strings.Split(response_tokens, "&")

		oauth_token_secret_array := strings.Split(response_tokens_array[0], "=")
		consumer.Request_Token_Secret = oauth_token_secret_array[1]

		oauth_token_array := strings.Split(response_tokens_array[2], "=")
		consumer.Request_Token = oauth_token_array[1]
	}
}

func (consumer *oauthConsumer) GetVeriferandRealmId(r *http.Request) {
	values, err := url.ParseQuery(r.URL.String())
	if err != nil {
		fmt.Println("Callback Value Error: ", err)
		return
	}

	consumer.Verifier = values.Get("oauth_verifier")
	consumer.RealmId = values.Get("realmId")
}

func (consumer *oauthConsumer) GetAccessToken() {

	// Set the NOnce and Timestamp for Access Signature and Token
	// If they change during Signing and Call it fucks it up
	// So I call them ahead of time to set them.
	//consumer.CreateNOnce()
	//consumer.CreateTimestamp()

	oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
	oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
	oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
	oauth_signature := "oauth_signature=" + consumer.CreateSignature("GET", "access") + "&"
	oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
	oauth_request_token := "oauth_token=" + consumer.Request_Token + "&"
	oauth_verifier := "oauth_verifier=" + consumer.Verifier + "&"
	oauth_version := "oauth_version=" + consumer.Version

	oauthHDR := oauth_consumer_key + oauth_nonce + oauth_signature_method + oauth_timestamp + oauth_request_token + oauth_verifier + oauth_version + "&" + oauth_signature

	client := &http.Client{}

	// Send the Access Request
	request, err := http.NewRequest("GET", consumer.Access_URL+"?"+oauthHDR, nil)

	if err != nil {
		fmt.Println("Request Error: ", err)
		return
	}

	// Get the Reponse and check the Status
	response, err := client.Do(request)
	if response.Status != "200 OK" {
		fmt.Println("Response Status: ", response.Status)
		var buf [512]byte
		reader := response.Body
		for {
			n, err := reader.Read(buf[0:])
			if err != nil {
				fmt.Println("Response Error:", err)
				return
			}
			fmt.Println("Response Body: ", string(buf[0:n]))
			return
		}
		fmt.Println("Response Status Code Error:", err)
		return
	}

	// Take the Response and Extract the Access Tokens
	var buf [512]byte
	reader := response.Body
	for {
		n, err := reader.Read(buf[0:])
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Println(string(buf[0:n]))
		response_tokens := string(buf[0:n])
		response_tokens_array := strings.Split(response_tokens, "&")

		oauth_token_secret_array := strings.Split(response_tokens_array[0], "=")
		consumer.Access_Token_Secret = oauth_token_secret_array[1]

		oauth_token_array := strings.Split(response_tokens_array[1], "=")
		consumer.Access_Token = oauth_token_array[1]
	}

}

func Sign(message string, key string) string {

	hash := hmac.New(sha1.New, []byte(key))
	hash.Write([]byte(message))
	rawsignature := hash.Sum(nil)
	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)

	return url.QueryEscape(string(base64signature))

}
