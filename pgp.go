package pgp

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// KeyProvider returns a plain text armored pgp usable key.
// parameter scope is either public or private - indicates the usage of the key.
type KeyProvider func(recipientEMail string, scope string) (string, error)

// Encrypt pipes the plainMessage through ASCII-Armoring and pgp encryption
func Encrypt(plainMessage io.WriterTo, recipientMails []string, keyProvider KeyProvider) (io.WriterTo, error) {
	// we have to scope public, since we want to encrypt against the public keys of given recipient
	entities, err := getEntitiesByKeyProvider(recipientMails, keyProvider, "public")
	if err != nil {
		return nil, err
	}

	var encryptedOutputBuffer bytes.Buffer

	armoringPipe, err := armor.Encode(&encryptedOutputBuffer, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	defer armoringPipe.Close()

	encryptionWriter, err := openpgp.Encrypt(armoringPipe, entities, nil, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return nil, err
	}
	defer encryptionWriter.Close()

	_, err = plainMessage.WriteTo(encryptionWriter)
	if err != nil {
		return nil, err
	}

	return &encryptedOutputBuffer, nil
}

// Sign returns a io.WriterTo "containing" the armored signature
func Sign(plainMessage io.WriterTo, senderMail string, provider KeyProvider, passphrase []byte) (io.WriterTo, error) {
	// we need the private key for signing
	entity, err := getSingleEntity(senderMail, provider, "private", passphrase)
	if err != nil {
		return nil, err
	}

	var inputBuffer bytes.Buffer
	if _, err := plainMessage.WriteTo(&inputBuffer); err != nil {
		return nil, err
	}

	writer := new(bytes.Buffer)
	err = openpgp.ArmoredDetachSign(writer, entity, &inputBuffer, nil)
	if err != nil {
		return nil, err
	}
	return writer, nil
}
