package pgp

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func getEntitiesByKeyProvider(keyMailaddresses []string, provider KeyProvider, scope string) (openpgp.EntityList, error) {
	var entities openpgp.EntityList

	for _, reciepientMail := range keyMailaddresses {
		entity, err := getSingleEntity(reciepientMail, provider, scope, nil)
		if err != nil {
			return nil, err
		}

		entities = append(entities, entity)
	}

	return entities, nil
}

func getSingleEntity(mailAddress string, provider KeyProvider, scope string, passphrase []byte) (*openpgp.Entity, error) {
	key, keyErr := provider(mailAddress, scope)
	if keyErr != nil {
		return nil, keyErr
	}

	entity, entityErr := newEntity(key)
	if entityErr != nil {
		return nil, entityErr
	}

	switch scope {
	case "public":
		if entity.PrimaryKey == nil {
			return nil, fmt.Errorf("scoped public, but no public key provided for %s", key)
		}
	case "private":
		if entity.PrivateKey == nil {
			return nil, fmt.Errorf("scoped private, but no private key provided for %s", key)
		}
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, err
		}
	}

	return entity, nil
}

// newEntity converts a pgp key passed as a string to an openpgp.Entity
func newEntity(key string) (*openpgp.Entity, error) {
	strReader := strings.NewReader(key)

	block, err := armor.Decode(strReader)
	if err != nil {
		return nil, err
	}

	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	return entity, err
}
