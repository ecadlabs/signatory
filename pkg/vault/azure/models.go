package azure

import (
	"time"

	"github.com/ecadlabs/signatory/pkg/jwk"
)

type keyVaultError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	InnerError *keyVaultError `json:"innererror"`
}

type keyVaultErrorResponse struct {
	Error *keyVaultError `json:"error"`
}

type keyListResult struct {
	NextLink string     `json:"nextLink"`
	Value    []*keyItem `json:"value"`
}

type keyItem struct {
	Attributes keyAttributes          `json:"attributes"`
	KeyID      string                 `json:"kid"`
	Managed    bool                   `json:"managed"`
	Tags       map[string]interface{} `json:"tags"`
}

type keyBundle struct {
	Attributes keyAttributes          `json:"attributes"`
	Key        jwk.JWK                `json:"key"`
	Managed    bool                   `json:"managed"`
	Tags       map[string]interface{} `json:"tags"`
}

type keyAttributes struct {
	Created       int    `json:"created"`
	Enabled       bool   `json:"enabled"`
	Exp           int    `json:"exp"`
	Nbf           int    `json:"nbf"`
	RecoveryLevel string `json:"recoveryLevel"`
	Updated       int    `json:"updated"`
}

type signRequest struct {
	Algorithm string `json:"alg"`
	Value     string `json:"value"`
}

type keyOperationResult struct {
	KeyID string `json:"kid"`
	Value string `json:"value"`
}

type importRequest struct {
	Attributes *keyAttributes         `json:"attributes,omitempty"`
	Key        *jwk.JWK               `json:"key"`
	Tags       map[string]interface{} `json:"tags,omitempty"`
	Hsm        bool                   `json:"hsm"`
}

type availabilityStatusRecentlyResolved struct {
	ResolvedTime            time.Time `json:"resolvedTime"`
	UnavailabilitySummary   string    `json:"unavailabilitySummary"`
	UnavailableOccurredTime time.Time `json:"unavailableOccurredTime"`
}

type availabilityStatusRecommendedAction struct {
	Action        string `json:"action"`
	ActionURL     string `json:"actionUrl"`
	ActionURLText string `json:"actionUrlText"`
}

type availabilityStatusServiceImpactingEvent struct {
	CorrelationID               string                                   `json:"correlationId"`
	EventStartTime              time.Time                                `json:"eventStartTime"`
	EventStatusLastModifiedTime time.Time                                `json:"eventStatusLastModifiedTime"`
	IncidentProperties          *serviceImpactingEventIncidentProperties `json:"incidentProperties"`
	Status                      *serviceImpactingEventStatus             `json:"status"`
}

type serviceImpactingEventIncidentProperties struct {
	IncidentType string `json:"incidentType"`
	Region       string `json:"region"`
	Service      string `json:"service"`
	Title        string `json:"title"`
}

type serviceImpactingEventStatus struct {
	Value string `json:"value"`
}

type availabilityStatusProperties struct {
	AvailabilityState        string                                     `json:"availabilityState"`
	DetailedStatus           string                                     `json:"detailedStatus"`
	HealthEventCategory      string                                     `json:"healthEventCategory"`
	HealthEventCause         string                                     `json:"healthEventCause"`
	HealthEventID            string                                     `json:"healthEventId"`
	HealthEventType          string                                     `json:"healthEventType"`
	OccurredTime             time.Time                                  `json:"occurredTime"`
	ReasonChronicity         string                                     `json:"reasonChronicity"`
	ReasonType               string                                     `json:"reasonType"`
	RecentlyResolved         *availabilityStatusRecentlyResolved        `json:"recentlyResolved"`
	RecommendedActions       []*availabilityStatusRecommendedAction     `json:"recommendedActions"`
	ReportedTime             time.Time                                  `json:"reportedTime"`
	ResolutionETA            string                                     `json:"resolutionETA"`
	RootCauseAttributionTime time.Time                                  `json:"rootCauseAttributionTime"`
	ServiceImpactingEvents   []*availabilityStatusServiceImpactingEvent `json:"serviceImpactingEvents"`
	Summary                  string                                     `json:"summary"`
}

type resourceHealthAvailabilityStatus struct {
	ID         string                       `json:"id"`
	Location   string                       `json:"location"`
	Name       string                       `json:"name"`
	Properties availabilityStatusProperties `json:"properties"`
	Type       string                       `json:"type"`
}

const (
	availabilityStatusAvailable   = "Available"
	availabilityStatusDegraded    = "Degraded"
	availabilityStatusUnavailable = "Unavailable"
	availabilityStatusUnknown     = "Unknown"
)
