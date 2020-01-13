package injectproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/pkg/labels"
)

type apiResponse struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data,omitempty"`
	ErrorType string          `json:"errorType,omitempty"`
	Error     string          `json:"error,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`

	ctx context.Context
}

func getAPIResponse(resp *http.Response) (*apiResponse, error) {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apir apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apir); err != nil {
		return nil, err
	}

	if apir.Status != "success" {
		return nil, fmt.Errorf("unexpected response status: %q", apir.Status)
	}

	apir.ctx = resp.Request.Context()

	return &apir, nil
}

func (a *apiResponse) setData(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	a.Data = json.RawMessage(b)
	return nil
}

func (a *apiResponse) Context() context.Context {
	return a.ctx
}

type rulesData struct {
	RuleGroups []*ruleGroup `json:"groups"`
}

type ruleGroup struct {
	Name     string  `json:"name"`
	File     string  `json:"file"`
	Rules    []rule  `json:"rules"`
	Interval float64 `json:"interval"`
}

type rule struct {
	*alertingRule
	*recordingRule
}

func (r *rule) Labels() labels.Labels {
	if r.alertingRule != nil {
		return r.alertingRule.Labels
	}
	return r.recordingRule.Labels
}

// MarshalJSON implements the json.Marshaler interface for rule.
func (r *rule) MarshalJSON() ([]byte, error) {
	if r.alertingRule != nil {
		return json.Marshal(r.alertingRule)
	}
	return json.Marshal(r.recordingRule)
}

// UnmarshalJSON implements the json.Unmarshaler interface for rule.
func (r *rule) UnmarshalJSON(b []byte) error {
	var ruleType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &ruleType); err != nil {
		return err
	}
	switch ruleType.Type {
	case "alerting":
		var alertingr alertingRule
		if err := json.Unmarshal(b, &alertingr); err != nil {
			return err
		}
		r.alertingRule = &alertingr
	case "recording":
		var recordingr recordingRule
		if err := json.Unmarshal(b, &recordingr); err != nil {
			return err
		}
		r.recordingRule = &recordingr
	default:
		return fmt.Errorf("failed to unmarshal rule: unknown type %q", ruleType.Type)
	}

	return nil
}

type alertingRule struct {
	Name        string        `json:"name"`
	Query       string        `json:"query"`
	Duration    float64       `json:"duration"`
	Labels      labels.Labels `json:"labels"`
	Annotations labels.Labels `json:"annotations"`
	Alerts      []*alert      `json:"alerts"`
	Health      string        `json:"health"`
	LastError   string        `json:"lastError,omitempty"`
	// Type of an alertingRule is always "alerting".
	Type string `json:"type"`
}

type recordingRule struct {
	Name      string        `json:"name"`
	Query     string        `json:"query"`
	Labels    labels.Labels `json:"labels,omitempty"`
	Health    string        `json:"health"`
	LastError string        `json:"lastError,omitempty"`
	// Type of a recordingRule is always "recording".
	Type string `json:"type"`
}

type alertsData struct {
	Alerts []*alert `json:"alerts"`
}

type alert struct {
	Labels      labels.Labels `json:"labels"`
	Annotations labels.Labels `json:"annotations"`
	State       string        `json:"state"`
	ActiveAt    *time.Time    `json:"activeAt,omitempty"`
	Value       string        `json:"value"`
}

// apiResponseModifier converts a Prometheus apiResponse modifier into a http Response modifier
// by converting the http response in flight into a Prometheus apiResponse,
// and passing the result into the given modifier.
//
// It replaces the response body with the mutated serialized version of the Prometheus apiResponse.
func apiResponseModifier(modifier func(*apiResponse) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			// Pass non-200 responses as-is.
			return nil
		}
		apir, err := getAPIResponse(resp)
		if err != nil {
			return errors.Wrap(err, "can't decode API response")
		}

		err = modifier(apir)
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		if err = json.NewEncoder(&buf).Encode(apir); err != nil {
			return errors.Wrap(err, "can't encode API response")
		}
		resp.Body = ioutil.NopCloser(&buf)
		resp.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}

		return nil
	}
}

func (r *routes) rules(resp *apiResponse) error {
	var rgs rulesData
	if err := json.Unmarshal([]byte(resp.Data), &rgs); err != nil {
		return errors.Wrap(err, "can't decode rules data")
	}

	lvalue := mustLabelValue(resp.Context())
	filtered := []*ruleGroup{}
	for _, rg := range rgs.RuleGroups {
		var rules []rule
		for _, rule := range rg.Rules {
			for _, lbl := range rule.Labels() {
				if lbl.Name == r.label && lbl.Value == lvalue {
					rules = append(rules, rule)
					break
				}
			}
		}
		if len(rules) > 0 {
			rg.Rules = rules
			filtered = append(filtered, rg)
		}
	}

	if err := resp.setData(&rulesData{RuleGroups: filtered}); err != nil {
		return errors.Wrap(err, "can't set data")
	}

	return nil
}

func (r *routes) alerts(resp *apiResponse) error {
	var data alertsData
	if err := json.Unmarshal([]byte(resp.Data), &data); err != nil {
		return errors.Wrap(err, "can't decode alerts data")
	}

	lvalue := mustLabelValue(resp.Context())
	filtered := []*alert{}
	for _, alert := range data.Alerts {
		for _, lbl := range alert.Labels {
			if lbl.Name == r.label && lbl.Value == lvalue {
				filtered = append(filtered, alert)
				break
			}
		}
	}

	if err := resp.setData(&alertsData{Alerts: filtered}); err != nil {
		return errors.Wrap(err, "can't set data")
	}

	return nil
}
