// Copyright 2018 David Lazar. All rights reserved.

// Endurance is a bot that announces activities (e.g., runs) to Slack.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"

	"github.com/dchest/safefile"
	"github.com/gorilla/sessions"
	"github.com/keybase/go-keybase-chat-bot/kbchat"
	"github.com/nlopes/slack"
)

var persistDir = flag.String("persist", "persist", "persistent data directory")
var apiRoot = "https://www.strava.com/api/v3"

type Server struct {
	hostname       string
	stravaConf     *oauth2.Config
	subscribeToken string

	kbAdminUsername string
	kbc             *kbchat.API

	workspaces map[string]*Workspace
}

type Config struct {
	Hostname        string
	KBAdminUsername string

	StravaClientID     string
	StravaClientSecret string

	Workspaces map[string]*Workspace
}

type Workspace struct {
	Type string // "slack" or "keybase"
	Name string // Team name for Keybase

	RunningChannelID string
	WeatherChannelID string

	// APIToken is used by Slack workspaces
	APIToken string
	rtm      *slack.RTM

	kbc *kbchat.API
}

var store *sessions.CookieStore

func init() {
	gob.Register(&oauth2.Token{})

	key := make([]byte, 32)
	rand.Read(key)
	store = sessions.NewCookieStore(key)
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
	if conf.Hostname == "" || conf.KBAdminUsername == "" || conf.StravaClientID == "" || conf.StravaClientSecret == "" || len(conf.Workspaces) == 0 {
		log.Fatalf("invalid config file (some fields missing)")
	}

	kbc, err := kbchat.Start(kbchat.RunOptions{})
	if err != nil {
		log.Fatalf("error creating keybase API: %s", err.Error())
	}

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

		subscribeToken: randomString(),

		kbc:             kbc,
		kbAdminUsername: conf.KBAdminUsername,

		workspaces: conf.Workspaces,
	}

	for name, ws := range conf.Workspaces {
		ws.Name = name
		switch ws.Type {
		case "slack":
			logFile := logFile(fmt.Sprintf("slack-%s.log", name))
			defer logFile.Close()
			slackLog := log.New(logFile, "", log.Lshortfile|log.LstdFlags)

			api := slack.New(ws.APIToken, slack.OptionDebug(true), slack.OptionLog(slackLog))
			ws.rtm = api.NewRTM()
			go ws.rtm.ManageConnection()
			go s.slackMessageLoop(ws)
		case "keybase":
			ws.kbc = kbc
		default:
			log.Fatalf("unknown workspace type: %q", ws.Type)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/strava/oauth", s.stravaOAuthHandler)
	mux.HandleFunc("/strava/follow", s.stravaFollowHandler)
	mux.HandleFunc("/strava/user", s.stravaUserHandler)
	mux.HandleFunc("/strava/webhook", s.stravaWebhookHandler)

	certManager := &autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(*persistDir, "ssl_keys")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(conf.Hostname),
	}
	httpErrorsFile := logFile("http_errors.log")
	defer httpErrorsFile.Close()
	httpServer := &http.Server{
		Addr:      ":https",
		Handler:   mux,
		TLSConfig: certManager.TLSConfig(),
		ErrorLog:  log.New(httpErrorsFile, "", log.LstdFlags),
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

	go s.keybaseMessageLoop()
	go s.weatherLoop()

	s.alertAdmin("Bot online: %s", conf.Hostname)

	select {}
}

func (s *Server) alertAdmin(format string, v ...interface{}) {
	str := fmt.Sprintf(format, v...)
	log.Println(str)
	tlfName := fmt.Sprintf("%s,%s", s.kbc.GetUsername(), s.kbAdminUsername)
	if _, err := s.kbc.SendMessageByTlfName(tlfName, str); err != nil {
		log.Printf("error sending keybase admin message: %s", err)
	}
}

func (ws *Workspace) sendMsg(dst string, msg string) {
	if ws.Type == "slack" {
		m := ws.rtm.NewOutgoingMessage(msg, dst)
		ws.rtm.SendMessage(m)
	}
	if ws.Type == "keybase" {
		if _, err := ws.kbc.SendMessageByTeamName(ws.Name, &dst, msg); err != nil {
			log.Printf("error sending keybase message to %q: %s", dst, err)
		}
	}
}

func (s *Server) keybaseMessageLoop() {
	sub, err := s.kbc.ListenForNewTextMessages()
	if err != nil {
		log.Fatalf("error listening for keybase messages: %s", err.Error())
	}

	for {
		msg, err := sub.Read()
		if err != nil {
			err := fmt.Errorf("failed to read keybase message: %s", err.Error())
			log.Println(err)
			s.alertAdmin("%s", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if msg.Message.Content.TypeName != "text" {
			continue
		}
		if msg.Message.Sender.Username == s.kbc.GetUsername() {
			continue
		}

		text := msg.Message.Content.Text.Body
		if strings.HasPrefix(text, "!testrun ") {
			target := strings.TrimPrefix(text, "!testrun ")
			ws, ok := s.workspaces[target]
			if !ok {
				s.kbc.SendMessage(msg.Message.Channel, "workspace %q not found", target)
				continue
			}
			ws.sendMsg(ws.RunningChannelID, "test run for workspace "+target)
		}

		if text == "!hsf" {
			outlook, err := getOutlook()
			if err != nil {
				continue
			}
			f := outlook.SummitOutlook.Forecast1
			str := fmt.Sprintf("Higher summits forecast for %s:  %s -- wind %s -- chill %s", f.Period, f.Prediction.Temperature, f.Prediction.Wind, f.Prediction.WindChill)
			s.kbc.SendMessage(msg.Message.Channel, str)
		}
	}
}

func (s *Server) slackMessageLoop(ws *Workspace) {
	for msg := range ws.rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.MessageEvent:
			if ev.Text == "!follow" {
				text := fmt.Sprintf("https://%s/strava/follow?workspace=%s", s.hostname, ws.Name)
				msg := ws.rtm.NewOutgoingMessage(text, ev.Channel)
				ws.rtm.SendMessage(msg)
			}
		case *slack.RTMError:
			log.Printf("slack error: %s\n", ev.Error())
		}
	}
}

func logFile(name string) *os.File {
	f, err := os.OpenFile(filepath.Join(*persistDir, name), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	return f
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<html><a href="https://github.com/davidlazar/endurance">Endurance</a> Bot!</html>`))
}

func (s *Server) stravaFollowHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "strava")

	workspace := r.URL.Query().Get("workspace")
	if workspace != "" {
		_, ok := s.workspaces[workspace]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown workspace: %q", workspace), http.StatusBadRequest)
			return
		}
		session.Values["workspace"] = workspace
	}

	oauthState := randomString()
	session.Values["oauth-state"] = oauthState
	session.Save(r, w)

	authURL := s.stravaConf.AuthCodeURL(oauthState, oauth2.AccessTypeOffline)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) stravaOAuthHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "strava")

	if r.FormValue("state") != session.Values["oauth-state"] {
		http.Error(w, "invalid oauth state value (are cookies enabled?)", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	token, err := s.stravaConf.Exchange(context.Background(), code)
	if err != nil {
		err = fmt.Errorf("oauth exchange error: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		s.alertAdmin(err.Error())
		return
	}

	session.Values["stravaToken"] = token
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %s", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/strava/user", http.StatusFound)
}

type StravaUser struct {
	ID    int
	Name  string
	Token *oauth2.Token

	Workspaces []string
}

func (s *Server) loadStravaUser(id int) (*StravaUser, error) {
	path := filepath.Join(*persistDir, "users", fmt.Sprintf("%d.strava", id))
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	u := new(StravaUser)
	err = json.Unmarshal(data, u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (u *StravaUser) Save() error {
	path := filepath.Join(*persistDir, "users", fmt.Sprintf("%d.strava", u.ID))
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		panic(err)
	}
	return safefile.WriteFile(path, data, 0660)
}

type templateData struct {
	ID         int
	Name       string
	Workspaces map[string]bool
	Message    string
}

var userTemplate = template.Must(template.New("user").Parse(`<!doctype html>
<html>
<head>
  <link rel='stylesheet' href='https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css'>
</head>
<body>
<h1>Strava User Settings</h1>
<form action="/strava/user" method="post">
  <label>Strava ID: <input type="text" value="{{.ID}}" readonly></label><br>
  <label>Name: <input type="text" value="{{.Name}}" readonly></label><br>
  <fieldset>
    <legend>Post runs to these workspaces:</legend>
	{{range $name, $checked := .Workspaces}}
	<label><input name="workspaces" value="{{$name}}" type="checkbox"{{if $checked}}checked{{end}}> {{$name}}</label>
	{{end}}
  </fieldset><br>
  <button type="submit">Save</button>
</form>
<br><br>
<p>{{.Message}}</p>
</body>
</html>`))

func (s *Server) stravaUserHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "strava")
	v, ok := session.Values["stravaToken"]
	if !ok {
		http.Error(w, "not logged in!", http.StatusBadRequest)
		return
	}
	token := v.(*oauth2.Token)

	athlete, err := s.getAthlete(token)
	if err != nil {
		err = fmt.Errorf("failed to get strava athlete info from oauth token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.alertAdmin(err.Error())
		return
	}
	td := templateData{
		ID:         athlete.ID,
		Name:       athlete.FirstName,
		Workspaces: make(map[string]bool),
	}
	for k := range s.workspaces {
		td.Workspaces[k] = false
	}

	if r.Method == "GET" {
		u, err := s.loadStravaUser(athlete.ID)
		if err == nil {
			for _, name := range u.Workspaces {
				td.Workspaces[name] = true
			}
		}
		if name, ok := session.Values["workspace"]; ok {
			td.Workspaces[name.(string)] = true
		}
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("failed to parse form: %s", err), http.StatusInternalServerError)
			return
		}
		names := r.Form["workspaces"]
		for _, name := range names {
			_, ok := s.workspaces[name]
			if !ok {
				td.Message = fmt.Sprintf("Unknown workspace: %q", name)
				goto Done
			}
			td.Workspaces[name] = true
		}
		u := &StravaUser{
			ID:         athlete.ID,
			Name:       athlete.FirstName,
			Token:      token,
			Workspaces: names,
		}
		err := u.Save()
		if err != nil {
			errmsg := fmt.Sprintf("Error saving user state: %s", err)
			td.Message = errmsg
			log.Println(errmsg)
		} else {
			td.Message = fmt.Sprintf("Saved settings for user %d", athlete.ID)
			s.alertAdmin("Updated Strava user settings for %s (%d): %v", u.Name, u.ID, u.Workspaces)
		}
	}

Done:
	err = userTemplate.Execute(w, td)
	if err != nil {
		panic(err)
	}
}

type DetailedAthlete struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstname"`

	client *http.Client
}

func (s *Server) getAthlete(token *oauth2.Token) (*DetailedAthlete, error) {
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
	err = json.Unmarshal(data, v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal detailed athlete: %s: %s", err, data)
	}
	v.client = client

	return v, nil
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
	log.Printf("strava webhook event: %#v", event)

	if event.ObjectType == "activity" && (event.AspectType == "create" || event.AspectType == "update") {
		go func() {
			u, err := s.loadStravaUser(event.OwnerID)
			if err != nil {
				s.alertAdmin("failed to load user state for user id %d: %s", event.OwnerID, err)
				return
			}

			athlete, err := s.getAthlete(u.Token)
			if err != nil {
				s.alertAdmin("failed to get athlete info for user id %d: %s", event.OwnerID, err)
				return
			}

			activity, err := getActivity(athlete.client, event.ObjectID)
			if err != nil {
				s.alertAdmin("failed to get activity %d (user %d): %s", event.ObjectID, event.OwnerID, err)
				return
			}

			msg := activity.MsgFormat(athlete.FirstName)
			if event.AspectType != "create" {
				msg = msg + "  _(" + event.AspectType + ")_"
			}
			for _, name := range u.Workspaces {
				ws, ok := s.workspaces[name]
				if !ok {
					continue
				}
				ws.sendMsg(ws.RunningChannelID, msg)
			}
		}()
	}

	w.Write([]byte("OK"))
}

type SummaryActivity struct {
	ID          int       `json:"id"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	StartDate   time.Time `json:"start_date"`
	Distance    float64   `json:"distance"`
	MovingTime  int       `json:"moving_time"`
	ElapsedTime int       `json:"elapsed_time"`
	Gain        float64   `json:"total_elevation_gain"`
}

func (s *SummaryActivity) MsgFormat(user string) string {
	miles := s.Distance / 1609.34 // meters in a mile
	elapsedTime := calcTime(s.ElapsedTime)
	racePace := calcPace(miles, float64(s.ElapsedTime))
	movingPace := calcPace(miles, float64(s.MovingTime))
	pause := time.Duration(time.Duration(s.ElapsedTime-s.MovingTime) * time.Second)
	gain := s.Gain * 3.28 // meters to feet

	summary := fmt.Sprintf("*%s* %s *%s*: %0.1fmi in %s", user, emoji(s.Type), s.Name, miles, elapsedTime)
	if gain >= 400 {
		summary += fmt.Sprintf(", *+%0.0fft*", gain)
	}
	summary += fmt.Sprintf(", %s race pace", racePace)
	if pause >= 60 {
		summary += fmt.Sprintf(", %s pace without %s pause", movingPace, pause)
	}

	return summary
}

func getActivity(client *http.Client, activityID int) (*SummaryActivity, error) {
	url := fmt.Sprintf("%s/activities/%d", apiRoot, activityID)
	resp, err := client.Get(url)
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

func (s *Server) existingSubscription() bool {
	u := fmt.Sprintf("%s/push_subscriptions?client_id=%s&client_secret=%s", apiRoot, s.stravaConf.ClientID, s.stravaConf.ClientSecret)
	resp, err := http.Get(u)
	if err != nil {
		log.Fatalf("GET strava /push_subscriptions: %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read push_subscriptions body: %s", err)
	}
	var subs []map[string]interface{}
	if err := json.Unmarshal(body, &subs); err != nil {
		log.Fatalln(err)
	}
	if len(subs) == 0 {
		return false
	}
	if subs[0]["callback_url"] == "https://"+s.hostname+"/strava/webhook" {
		return true
	}
	return false
}

func (s *Server) subscribeWebhook() {
	if s.existingSubscription() {
		return
	}

	resp, err := http.PostForm(apiRoot+"/push_subscriptions", url.Values{
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

	files, err := filepath.Glob(filepath.Join(usersPath, "*.strava"))
	if err != nil {
		log.Fatal(err)
	}
	ids := make([]int, len(files))
	for i, file := range files {
		s := strings.TrimSuffix(filepath.Base(file), ".strava")
		id, err := strconv.Atoi(s)
		if err != nil {
			log.Fatalf("invalid user state: %s: %s", file, err)
		}
		ids[i] = id
	}

	for _, id := range ids {
		u, err := s.loadStravaUser(id)
		if err != nil {
			log.Fatal(err)
		}
		athlete, err := s.getAthlete(u.Token)
		if err != nil {
			log.Printf("failed to load athlete %d: %s", id, err)
			continue
		}
		log.Printf("Loaded user: %s (%d)", athlete.FirstName, athlete.ID)
	}
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

func emoji(activityType string) string {
	switch activityType {
	case "Run":
		return "🏃"
	case "Hike":
		return "️⛰️"
	case "Ride":
		return "🚴"
	case "Walk":
		return "🚶"
	case "Swim":
		return "🏊"
	case "AlpineSki":
		return "⛷️"
	case "BackcountrySki":
		return "🏔️⛷️"
	case "Snowboard":
		return "🏂"
	case "IceSkate":
		return "⛸"
	case "InlineSkate":
		return "🛼"
	case "Kayaking":
		return "🚣"
	case "RockClimbing":
		return "🧗"
	case "Soccer":
		return "⚽"
	case "Yoga":
		return "🧘"
	}
	return "🤸(" + activityType + ")"
}

func randomString() string {
	k := make([]byte, 16)
	rand.Read(k)
	return base64.RawURLEncoding.EncodeToString(k)
}
