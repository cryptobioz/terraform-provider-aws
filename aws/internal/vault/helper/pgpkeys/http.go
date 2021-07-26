package pgpkeys

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/keybase/go-crypto/openpgp"
)

// FetchKeybasePubkey fetches a public key from an HTTP endpoint. The key is returned
// as base64-encoded string.
func FetchHTTPPubkey(url string) (publicKey string, err error) {
	client := cleanhttp.DefaultClient()
	if client == nil {
		err = fmt.Errorf("unable to create an http client")
		return
	}

	if len(url) == 0 {
		return
	}

	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	bodyString := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("got non-OK response: %d - %q", resp.StatusCode, bodyString)
		return
	}

	serializedEntity := bytes.NewBuffer(nil)
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(bodyString))
	if err != nil {
		return
	}

	if len(entityList) < 1 {
		err = fmt.Errorf("no key available")
		return
	}
	if entityList[0] == nil {
		err = fmt.Errorf("primary key is nil")
		return
	}

	serializedEntity.Reset()
	err = entityList[0].Serialize(serializedEntity)
	if err != nil {
		err = fmt.Errorf("error serializing entity: %w", err)
		return
	}

	publicKey = base64.StdEncoding.EncodeToString(serializedEntity.Bytes())
	return
}
