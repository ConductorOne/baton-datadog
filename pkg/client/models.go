package client

// OnCallScheduleAttributes represents the attributes of an on-call schedule.
type OnCallScheduleAttributes struct {
	Name     string `json:"name"`
	TimeZone string `json:"time_zone"`
}

// OnCallSchedule represents an on-call schedule in Datadog.
type OnCallSchedule struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes OnCallScheduleAttributes `json:"attributes"`
}

// SimpleOnCallScheduleList represents a simple list of schedules without pagination metadata.
type SimpleOnCallScheduleList struct {
	Schedules []OnCallSchedule `json:"schedules"`
}

// OnCallSchedulesResponse represents the response of the on-call schedules API.
type OnCallSchedulesResponse struct {
	Data []OnCallSchedule `json:"data"`
	Meta struct {
		Page struct {
			Type        string `json:"type"`
			Number      int    `json:"number"`
			Size        int    `json:"size"`
			Total       int    `json:"total"`
			FirstNumber int    `json:"first_number"`
			PrevNumber  *int   `json:"prev_number"`
			NextNumber  *int   `json:"next_number"`
			LastNumber  int    `json:"last_number"`
		} `json:"page"`
	} `json:"meta"`
}

// OnCallUserAttributes represents the attributes of an on-call user.
type OnCallUserAttributes struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// OnCallUser represents an on-call user in Datadog.
type OnCallUser struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"`
	Attributes OnCallUserAttributes `json:"attributes"`
}

// OnCallUserResponse represents the response of the on-call user API.
type OnCallUserResponse struct {
	Data OnCallUser `json:"data"`
}
