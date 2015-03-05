package main

import (
	"encoding/json"
	"fmt"
	"github.com/jiran/oauthv1"
	"gopkg.in/mgo.v2"
	"html/template"
	"net/http"
)

// Intialize the Consumer Object Globally
var consumer = oauthv1.NewConsumer("https://oauth.intuit.com/oauth/v1/get_access_token", "https://appcenter.intuit.com/Connect/Begin", "https://oauth.intuit.com/oauth/v1/get_request_token", "Insert Callback URL Example: http://app.example.com/callback", "Insert Your Consumer Key", "Insert Your Consumer Secret")

// The Main Function
func main() {
	http.HandleFunc("/reportHandler", reportHandler)
	http.HandleFunc("/success", successHandler)
	http.HandleFunc("/popup-success", popupSuccessHandler)
	http.HandleFunc("/access", accessTokenHandler)
	http.HandleFunc("/callback", callbackTokenHandler)
	http.HandleFunc("/request", requestTokenHandler)
	http.HandleFunc("/", rootHandler)
	http.ListenAndServe(":8080", nil)
} //End Main Function

// Web Server Listeners / Handlers
func rootHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("index.html")
	if err != nil {
		fmt.Println("Index Template Error: ", err)
		return
	}
	t.Execute(w, nil)
}

// Web Server Listeners / Handlers
func popupSuccessHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("popup_success.html")
	if err != nil {
		fmt.Println("Index Template Error: ", err)
		return
	}
	t.Execute(w, nil)
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("success.html")
	if err != nil {
		fmt.Println("Index Template Error: ", err)
		return
	}
	t.Execute(w, nil)
}

func requestTokenHandler(w http.ResponseWriter, r *http.Request) {
	consumer.GetRequestToken()
	http.Redirect(w, r, consumer.Authorize_URL+"?"+"oauth_token="+consumer.Request_Token, 302)
}

func callbackTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Pass the request to get the URL values from callback
	consumer.GetVeriferandRealmId(r)
	fmt.Println("OAuth Verifier: ", consumer.Verifier)
	fmt.Println("Realm ID: ", consumer.RealmId)
	fmt.Println("Request Token: ", consumer.Request_Token)
	http.Redirect(w, r, "/access", 302)
}

func accessTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Now Let's Get Our Access Token and Redirect to Succesful Page
	consumer.GetAccessToken()

	http.Redirect(w, r, "/popup-success", 302)
}

func reportHandler(w http.ResponseWriter, r *http.Request) {

	// Ok let's try hitting the APi now that we have the Access token!
	api_url := "https://qb.sbfinance.intuit.com/v3/company/" + consumer.RealmId + "/companyinfo/" + consumer.RealmId
	//from quickbooks API ex)https://qb.sbfinance.intuit.com/v3/company/1265493090/companyinfo/1265493090
	//api_url := "https://qb.sbfinance.intuit.com/v3/company/" + consumer.RealmId + "/reports/CashFlow"

	// Initial call to NOnce and Timestamp
	consumer.CreateNOnce()
	consumer.CreateTimestamp()

	oauth_token := "oauth_token=" + consumer.Access_Token + "&"
	oauth_nonce := "oauth_nonce=" + consumer.NOnce + "&"
	oauth_consumer_key := "oauth_consumer_key=" + consumer.Consumer_Key + "&"
	oauth_signature_method := "oauth_signature_method=" + consumer.Signature_Method + "&"
	oauth_timestamp := "oauth_timestamp=" + consumer.Timestamp + "&"
	oauth_version := "oauth_version=" + consumer.Version + "&"
	oauth_signature := "oauth_signature=" + consumer.CreateSignature("GET", api_url)

	oauthHDR := oauth_token + oauth_nonce + oauth_consumer_key + oauth_signature_method + oauth_timestamp + oauth_version + oauth_signature

	client := &http.Client{}

	request, err := http.NewRequest("GET", api_url+"?"+oauthHDR, nil)
	if err != nil {
		fmt.Println("Api Request Error: ", err)
	}

	request.Header.Add("Accept", "application/json")

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

	// Take the Response and Shove the initial Company Data into Mongo
	type cmp struct {
		CompanyName string
	}

	var buf [4096]byte
	reader := response.Body
	for {
		n, err := reader.Read(buf[0:])
		if err != nil {
			fmt.Println("error:", err)
			return
		}

		//err = json

		//Input json data into mongo
		//Initialize MongoDB
		session, err := mgo.Dial("localhost")
		if err != nil {
			panic(err)
		}
		collection := session.DB("qbdata").C("Company_") //test this + cmp.CompanyName)
		document := string(buf[0:n])

		//added this for dynamic json Unmarshaling
		var dmap map[string]interface{}
		err = json.Unmarshal([]byte(document), &dmap)
		if err != nil {
			fmt.Printf("Can't Unmarshal document: %v\n", err)
			//return err
		}
		err = collection.Insert(dmap)
		//end dynamic json unmarshaling
		if err != nil {
			fmt.Printf("Can't insert document: %v\n", err)
		}
	}
}
