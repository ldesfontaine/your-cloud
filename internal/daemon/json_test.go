package daemon

import (
	"encoding/json"
	"io"
)

func jsonNewStrictDecoder(reader io.Reader) *json.Decoder {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	return decoder
}
