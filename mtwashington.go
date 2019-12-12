package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type outlook struct {
	LastUpdated   string
	SummitOutlook summitOutlook
}

type summitOutlook struct {
	Forecast1 *forecast
	Forecast2 *forecast
	Forecast3 *forecast
	Forecast4 *forecast
}

type forecast struct {
	Period     string
	Prediction prediction `json:"Imperial"`
}

type prediction struct {
	Temperature string
	Wind        string
	WindChill   string
}

var numRE = regexp.MustCompile(`\d+`)

func (p prediction) windNums() []int {
	wss := numRE.FindAllString(p.Wind, -1)
	var winds []int
	for _, ws := range wss {
		wind, err := strconv.Atoi(ws)
		if err != nil {
			continue
		}
		winds = append(winds, wind)
	}
	return winds
}

func (p prediction) isGood() bool {
	for _, wind := range p.windNums() {
		if wind > 15 {
			return false
		}
	}
	return true
}

func (o outlook) goodDays() []*forecast {
	os := o.SummitOutlook
	forecasts := []*forecast{os.Forecast1, os.Forecast2, os.Forecast3, os.Forecast4}

	var good []*forecast
	for _, forecast := range forecasts {
		if strings.Contains(forecast.Period, "Night") {
			continue
		}
		if !forecast.Prediction.isGood() {
			continue
		}
		good = append(good, forecast)
	}

	return good
}

func getOutlook() (*outlook, error) {
	resp, err := http.Get("https://www.mountwashington.org/uploads/json/outlook.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http response: %s", resp.Status)
	}

	outlook := new(outlook)
	err = json.NewDecoder(resp.Body).Decode(outlook)
	return outlook, err
}

func (s *Server) weatherLoop() {
	for {
		outlook, err := getOutlook()
		if err != nil {
			s.alertAdmin("fetching weather outlook failed: %s", err)
			time.Sleep(6 * time.Hour)
			continue
		}

		goodDays := outlook.goodDays()
		for _, forecast := range goodDays {
			msg := fmt.Sprintf("Higher summits forecast for %s is looking good! Wind: %s", forecast.Period, forecast.Prediction.Wind)
			for _, ws := range s.workspaces {
				if ws.WeatherChannelID == "" {
					continue
				}
				ws.sendMsg(ws.WeatherChannelID, msg)
			}
		}

		time.Sleep(24 * time.Hour)
	}
}
