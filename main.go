// Copyright 2018 David Lazar. All rights reserved.

// Endurance is a bot that announces activities (e.g., runs) to Slack.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"

	"github.com/nlopes/slack"
)

var persistDir = flag.String("persist", "persist", "persistent data directory")
var apiRoot = "https://www.strava.com/api/v3"

type Server struct {
	hostname string

	stravaConf  *oauth2.Config
	stravaUsers sync.Map // map[id]*StravaUser

	slackRTM          *slack.RTM
	slackChannel      string
	slackAdminChannel string

	subscribeToken string
}

type Config struct {
	Hostname string

	StravaClientID     string
	StravaClientSecret string

	SlackAPIToken       string
	SlackChannelID      string
	SlackAdminChannelID string
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(*persistDir, 0600); err != nil {
		log.Fatal(err)
	}
	confData, err := ioutil.ReadFile(filepath.Join(*persistDir, "config.json"))
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	if err := json.Unmarshal(confData, conf); err != nil {
		log.Fatalf("error parsing config.json: %s", err)
	}
	if conf.Hostname == "" || conf.StravaClientID == "" || conf.StravaClientSecret == "" || conf.SlackAPIToken == "" || conf.SlackChannelID == "" || conf.SlackAdminChannelID == "" {
		log.Fatalf("invalid config file (some fields missing)")
	}

	logger := log.New(os.Stdout, "slack-bot: ", log.Lshortfile|log.LstdFlags)
	api := slack.New(conf.SlackAPIToken, slack.OptionDebug(false), slack.OptionLog(logger))

	rtm := api.NewRTM()
	go rtm.ManageConnection()

	s := &Server{
		hostname: conf.Hostname,

		stravaConf: &oauth2.Config{
			ClientID:     conf.StravaClientID,
			ClientSecret: conf.StravaClientSecret,
			Scopes:       []string{"activity:read_all"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.strava.com/oauth/authorize",
				TokenURL: "https://www.strava.com/oauth/token",
			},
			RedirectURL: "https://" + conf.Hostname + "/strava/oauth",
		},

		slackRTM:          rtm,
		slackChannel:      conf.SlackChannelID,
		slackAdminChannel: conf.SlackAdminChannelID,
		subscribeToken:    randomString(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/strava/oauth", s.stravaOAuthHandler)
	mux.HandleFunc("/strava/follow", s.stravaFollowHandler)
	mux.HandleFunc("/strava/webhook", s.stravaWebhookHandler)

	certManager := &autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(*persistDir, "ssl_keys")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(conf.Hostname),
	}
	httpServer := &http.Server{
		Addr:      ":https",
		Handler:   mux,
		TLSConfig: certManager.TLSConfig(),
	}
	go func() {
		err := httpServer.ListenAndServeTLS("", "")
		log.Fatal(err)
	}()

	go func() {
		err := http.ListenAndServe(":http", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "https://"+req.Host+req.URL.String(), http.StatusMovedPermanently)
		}))
		log.Fatal(err)
	}()

	s.loadUsers()
	s.subscribeWebhook()

	for msg := range rtm.IncomingEvents {
		_ = msg
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<html>Endurance Bot!
	<a href="/strava/follow">Authorize</a> Endurance to follow your runs on Strava.</html>`))
}

func getOAuthState(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Unclear if this is a great idea.
	st, err := r.TLS.ExportKeyingMaterial("oauth-state", nil, 16)
	if err != nil {
		http.Error(w, "failed to extract oauth state: "+err.Error(), http.StatusBadRequest)
		return "", false
	}
	state := base64.RawURLEncoding.EncodeToString(st)
	return state, true
}

func (s *Server) stravaFollowHandler(w http.ResponseWriter, r *http.Request) {
	state, ok := getOAuthState(w, r)
	if !ok {
		return
	}

	authURL := s.stravaConf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) stravaOAuthHandler(w http.ResponseWriter, r *http.Request) {
	state, ok := getOAuthState(w, r)
	if !ok {
		return
	}
	if state != r.FormValue("state") {
		http.Error(w, "bad state value: "+r.FormValue("state"), http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	tok, err := s.stravaConf.Exchange(context.Background(), code)
	if err != nil {
		err = fmt.Errorf("oauth exchange error: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		s.alertAdmin(err.Error())
		return
	}

	user, err := s.loadAthlete(tok)
	if err != nil {
		err = fmt.Errorf("failed to load strava athlete from oauth token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.alertAdmin(err.Error())
	}

	// Persist the OAuth token.
	tokenJSON, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		panic(err)
	}
	path := filepath.Join(*persistDir, "users", fmt.Sprintf("%d.token", user.ID))
	err = ioutil.WriteFile(path, tokenJSON, 0600)
	if err != nil {
		err = fmt.Errorf("failed to persist oauth token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.alertAdmin(err.Error())
	}

	msg := fmt.Sprintf("Strava user %s (%d) is now connected to Endurance. Keep running!", user.Name, user.ID)
	w.Write([]byte(msg))
	s.alertAdmin("New Strava user: %s (%d)", user.Name, user.ID)
}

type DetailedAthlete struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstname"`
}

type StravaUser struct {
	ID     int
	Name   string
	Client *http.Client
}

func (s *Server) loadAthlete(token *oauth2.Token) (*StravaUser, error) {
	client := s.stravaConf.Client(context.Background(), token)

	resp, err := client.Get(apiRoot + "/athlete")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response for /athlete: %s: %s", resp.Status, data)
	}
	// TODO handle http.StatusUnauthorized (especially when loading users at startup)

	v := new(DetailedAthlete)
	err = json.Unmarshal(data, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal detailed athlete: %s: %s", err, data)
	}

	user := &StravaUser{
		ID:     v.ID,
		Name:   v.FirstName,
		Client: client,
	}
	s.stravaUsers.Store(v.ID, user)
	return user, nil
}

type WebhookEvent struct {
	ObjectType string `json:"object_type"` // "activity" or "athlete"
	AspectType string `json:"aspect_type"` // "create", "update", "delete"
	ObjectID   int    `json:"object_id"`
	OwnerID    int    `json:"owner_id"`
}

func (s *Server) stravaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if r.FormValue("hub.verify_token") != s.subscribeToken {
			http.Error(w, "bad verify token", http.StatusBadRequest)
			return
		}
		challenge := r.FormValue("hub.challenge")
		out, err := json.Marshal(map[string]string{"hub.challenge": challenge})
		if err != nil {
			panic(err)
		}
		w.Write(out)
		return
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	event := new(WebhookEvent)
	err = json.Unmarshal(data, event)
	if err != nil {
		s.alertAdmin("failed to unmarshal webhook event: %s: %s", err, data)
		return
	}

	if event.ObjectType == "activity" && event.AspectType == "create" {
		go func() {
			v, ok := s.stravaUsers.Load(event.OwnerID)
			if !ok {
				s.alertAdmin("received event for unregistered user %d", event.OwnerID)
				return
			}
			user := v.(*StravaUser)

			activity, err := s.getActivity(user, event.ObjectID)
			if err != nil {
				s.alertAdmin("failed to get activity %d (user %d): %s", event.ObjectID, event.OwnerID, err)
				return
			}

			msg := fmt.Sprintf("*%s* %s", user.Name, activity.MsgFormat())
			log.Printf("Announce: %s", msg)
			out := s.slackRTM.NewOutgoingMessage(msg, s.slackChannel)
			s.slackRTM.SendMessage(out)
		}()
	}

	w.Write([]byte("OK"))
}

type SummaryActivity struct {
	ID          int       `json:"id"`
	Type        string    `json:"type"`
	StartDate   time.Time `json:"start_date"`
	Distance    float64   `json:"distance"`
	MovingTime  int       `json:"moving_time"`
	ElapsedTime int       `json:"elapsed_time"`
}

func (s *SummaryActivity) MsgFormat() string {
	miles := s.Distance / 1609.34 // meters in a mile
	elapsedTime := calcTime(s.ElapsedTime)
	racePace := calcPace(miles, float64(s.ElapsedTime))
	movingPace := calcPace(miles, float64(s.MovingTime))

	pause := time.Duration(time.Duration(s.ElapsedTime-s.MovingTime) * time.Second)
	return fmt.Sprintf("%s %0.1fmi in %s (%s pace, %s without %s of pause time)", activityPastTense(s.Type), miles, elapsedTime, racePace, movingPace, pause)
}

func (s *Server) getActivity(user *StravaUser, activityID int) (*SummaryActivity, error) {
	url := fmt.Sprintf("%s/activities/%d", apiRoot, activityID)
	resp, err := user.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response: %s: %s", resp.Status, body)
	}

	activity := new(SummaryActivity)
	err = json.Unmarshal(body, activity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal activity: %s: %s", err, body)
	}

	return activity, nil
}

func (s *Server) subscribeWebhook() {
	// NOTE: This URL is different from the API root used elsewhere.
	resp, err := http.PostForm("https://api.strava.com/api/v3/push_subscriptions", url.Values{
		"client_id":     {s.stravaConf.ClientID},
		"client_secret": {s.stravaConf.ClientSecret},
		"callback_url":  {"https://" + s.hostname + "/strava/webhook"},
		"verify_token":  {s.subscribeToken},
	})
	if err != nil {
		log.Fatalf("POST strava /push_subscriptions: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		log.Printf("Subscribed to Strava webhook")
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read push_subscriptions body: %s", err)
	}
	log.Fatalf("failed to subscribe to strava webhook: %s: %s", resp.Status, body)
}

func (s *Server) loadUsers() {
	usersPath := filepath.Join(*persistDir, "users")
	err := os.MkdirAll(usersPath, 0700)
	if err != nil {
		log.Fatal(err)
	}

	files, err := filepath.Glob(filepath.Join(usersPath, "*.token"))
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		token := new(oauth2.Token)
		err = json.Unmarshal(data, token)
		if err != nil {
			log.Fatalf("failed to unmarshal token from %s: %s", file, err)
		}
		user, err := s.loadAthlete(token)
		if err != nil {
			log.Printf("failed to load athlete from %s: %s", file, err)
			continue
		}
		log.Printf("Loaded user: %s (%d)", user.Name, user.ID)
	}
}

func (s *Server) alertAdmin(format string, v ...interface{}) {
	str := fmt.Sprintf(format, v...)
	log.Println(str)
	go func() {
		msg := s.slackRTM.NewOutgoingMessage(str, s.slackAdminChannel)
		s.slackRTM.SendMessage(msg)
	}()
}

func calcTime(totalSeconds int) string {
	seconds := totalSeconds % 60
	minutes := (totalSeconds / 60) % 60
	hours := totalSeconds / (60 * 60)
	if hours == 0 {
		return fmt.Sprintf("%d:%02d", minutes, seconds)
	} else {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds)
	}
}

func calcPace(miles float64, seconds float64) string {
	if miles == 0.0 {
		return "0:00"
	}

	paceMin, paceFrac := math.Modf(seconds / 60.0 / miles)
	paceSec := int(paceFrac * 60.0)
	str := fmt.Sprintf("%d:%02d", int(paceMin), paceSec)
	return str
}

func activityPastTense(activityType string) string {
	switch activityType {
	case "Run":
		return "ran"
	case "Hike":
		return "hiked"
	case "Ride":
		return "rode"
	case "Walk":
		return "walked"
	case "Swim":
		return "swam"
	}
	return activityType
}

func randomString() string {
	k := make([]byte, 16)
	rand.Read(k)
	return base64.RawURLEncoding.EncodeToString(k)
}
