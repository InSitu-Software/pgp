package pgp

import (
	"bytes"
	"io"

	"gitlab.insitu.de/golang/database"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// KeyProvider returns a plain text armored pgp usable key.
// parameter scope is either public or private - indicates the usage of the key.
type KeyProvider func(recipientEMail string, scope string) (string, error)

func Encrypt(plainMessage io.WriterTo, recipientMails []string, keyProvider KeyProvider) (io.WriterTo, error) {
	// we have to scope public, since we want to encrypt against the public keys of given recipient
	entities, err := getEntitiesByKeyProvider(recipientMails, keyProvider, "public")
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	msg, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	defer msg.Close()

	w, err := openpgp.Encrypt(msg, entities, nil, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	_, err = plainMessage.WriteTo(w)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// / OLD

// retrievePubKeysFromDB Looks up all recipients in the array, in the DB and returns their public PGP Key in a string array (keys are stored armored).
func retrievePubKeysFromDB(recipients []string) ([]string, error) {
	var pubKeys []string

	tx, err := database.Connection.Beginx()
	if err != nil {
		return nil, err
	}

	query := "SELECT pgpkey FROM employeeapp.keyspgp WHERE recipient=$1"
	for _, recp := range recipients {
		var pubKey string

		err = tx.QueryRowx(query, recp).Scan(&pubKey)
		if err != nil {
			return nil, err
		}

		pubKeys = append(pubKeys, pubKey)
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return pubKeys, nil
}

// preparePGPEntities pubKeys holds armored public PGP keys which get translated to openpgp.Entities, needed for the Encryption
func preparePGPEntities(pubKeys []string) ([]*openpgp.Entity, error) {
	var entities []*openpgp.Entity

	for _, pupKey := range pubKeys {

		entity, err := getEntity(pupKey)
		if err != nil {
			return nil, err
		}

		entities = append(entities, entity)
	}

	return entities, nil
}

// SigPGP Result is armored
func SigPGP(message []byte, signer string, password string) ([]byte, error) {
	var signatureKey string
	err := database.Connection.QueryRowx("SELECT private FROM employeeapp.crypto_keys WHERE id=$1", signer).Scan(&signatureKey)
	if err != nil {
		return nil, err
	}

	entity, err := getEntity(signatureKey)
	if err != nil {
		return nil, err
	}

	err = entity.PrivateKey.Decrypt([]byte(password))
	if err != nil {
		return nil, err
	}

	for _, subkey := range entity.Subkeys {
		err = subkey.PrivateKey.Decrypt([]byte(password))
		if err != nil {
			return nil, err
		}
	}

	writer := new(bytes.Buffer)
	err = openpgp.ArmoredDetachSign(writer, entity, bytes.NewReader(message), nil)
	if err != nil {
		return nil, err
	}
	return writer.Bytes(), nil

}

// Encrypt Result is armored PGP
func OldEncrypt(messageToEncrypt []byte, recipients []string) (string, error) {
	pubKeys, err := retrievePubKeysFromDB(recipients)
	if err != nil {
		return "", err
	}

	entities, err := preparePGPEntities(pubKeys)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	msg, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	w, err := openpgp.Encrypt(msg, entities, nil, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return "", err
	}

	_, err = w.Write(messageToEncrypt)
	if err != nil {
		return "", err
	}

	// not closing writer or armored writer leads to a broken pgp message
	err = w.Close()
	if err != nil {
		return "", err
	}
	// msg needs to get closed after the writer get closed else broken pgp message
	err = msg.Close()
	if err != nil {
		return "", err
	}

	encryptedMsg := buf.String()
	return encryptedMsg, nil
}
