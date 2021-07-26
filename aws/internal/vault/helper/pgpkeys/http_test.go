package pgpkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/packet"
)

func TestFetchHTTPPubkeys(t *testing.T) {
	testURL := "https://keybase.io/hashicorp/pgp_keys.asc"
	publicKey, err := FetchHTTPPubkeys(testURL)
	if err != nil {
		t.Fatalf("bad: %v", err)
	}

	var fingerprint string
	data, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(data)))
	if err != nil {
		t.Fatalf("error parsing key: %v", err)
	}
	fingerprint = hex.EncodeToString(entity.PrimaryKey.Fingerprint[:])

	exp := "c874011f0ab405110d02105534365d9472d7468f"

	if !reflect.DeepEqual(fingerprint, exp) {
		t.Fatalf("fingerprint do not match; expected \n%#v\ngot\n%#v\n", exp, fingerprint)
	}
}
