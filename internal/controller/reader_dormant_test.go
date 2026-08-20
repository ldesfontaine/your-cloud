package controller

import (
	"context"
	"testing"
	"time"
)

// Le lecteur dormant répond l'indisponible du vocabulaire clos, sans
// instantané et sans erreur — l'état vrai d'une création dont le Relay
// n'existe pas encore. La garde tient les deux sens de la décision du
// 20 août 2026 : un dormant qui rendrait un instantané affirmerait un
// composant absent, un dormant qui rendrait `available` ouvrirait la porte
// de l'inventaire sur rien — et la mutation qui ferait l'un ou l'autre
// rougit ici.
func TestTheDormantReaderAnswersUnavailableAndNothingElse(t *testing.T) {
	snapshot, status, err := DormantRelayReader{}.Read(context.Background(), time.Now())
	if snapshot != nil {
		t.Fatal("a dormant reader must not invent a snapshot")
	}
	if status != RelayUnavailable {
		t.Fatalf("a dormant reader answers unavailable, not %q", status)
	}
	if err != nil {
		t.Fatalf("dormancy is a state, not an error: %v", err)
	}
}
