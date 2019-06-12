package pgp

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockPublicProvider(k string, scope string) (string, error) {
	switch scope {
	case "public":
		return qwertPub, nil
	case "private":
		return qwertPrivate, nil
	}

	return "", fmt.Errorf("wrong scope")
}

func Test_getEntitiesByKeyProvider(t *testing.T) {
	recipients := []string{"a@insitu.de", "b@insitu.de"}
	entities, err := getEntitiesByKeyProvider(recipients, mockPublicProvider, "public")
	if err != nil {
		t.Errorf("mocked keyprovider failed")
	}

	for _, e := range entities {
		if e.PrivateKey != nil {
			assert.Equal(t, nil, e.PrivateKey, "private key should not be set")
		}

		assert.NotEqual(t, nil, e.PrimaryKey, "public key must be set")
	}
}

// Just a small test to see if the right entity was returned (the Identity is checked)
func Test_getEntity(t *testing.T) {
	entity, err := getEntity(qwertPub)
	if err != nil {
		log.Fatal(err)
	}

	_, ok := entity.Identities["qwert <qwert@mail.xy>"]
	assert.Equal(t, ok, true)

	entity, err = getEntity(qwertPrivate)
	if err != nil {
		log.Fatal(err)
	}

	_, ok = entity.Identities["qwert <qwert@mail.xy>"]
	assert.Equal(t, ok, true)
}
