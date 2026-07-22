// Package protocol defines stable network and cryptographic identifiers shared
// by the current product roles. These identifiers version their own schema and
// never inherit a release number.
package protocol

const (
	RecoverySigningDomain    = "your-cloud/recovery-signing.v1"
	RecoveryKeyDomain        = "your-cloud/recovery-key-rotation.v1\x00"
	IdentityTranscriptDomain = "your-cloud/identity-transcript.v1\x00"
	HumanSessionDomain       = "your-cloud/human-session.v1\x00"
)

func ControllerServerName(infrastructureID string) string {
	return "controller." + infrastructureID + ".your-cloud.test"
}

func RelayReaderServerName(infrastructureID string) string {
	return "relay-reader." + infrastructureID + ".your-cloud.test"
}

func DeviceURI(infrastructureID, deviceID string) string {
	return "urn:your-cloud:device:v1:" + infrastructureID + ":" + deviceID
}
