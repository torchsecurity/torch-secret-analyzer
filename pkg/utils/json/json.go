package json

import "encoding/json"

func MustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func MustMarshalToString(v any) string {
	return string(MustMarshal(v))
}
