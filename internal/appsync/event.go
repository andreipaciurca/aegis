package appsync

type Event struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Error  bool   `json:"error,omitempty"`
}
