package pgp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"gitlab.insitu.de/golang/database"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const qwertPub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFn+3Y0BEADzhdYMw6wT3Yrxuypmh9P+bO6V+ryXD7nht8rERjAl4/R2tZUz
avVsMBS8avQB0xs9iuHEKjIqmCOMfJaXViOm/SNG293ojwqt8NxTPNLtQL+4zs7C
zL9A3YcAkU8DrW3JDnT+PwLjP9qImA7sRz6kaE2NCOKj5hBeGkp+6qM1FRIDbyph
5erBsj9Ipd12XL8eerJLKvcyqHDyDT9lGziXgawzI4QlqMHgDB0nEX5sHG4ar+g8
GfNc2JJq2v/SxmNt2bdXx6B7Js8nmXOUnwMqwvYeDCfnWENIrWZkAzrwo3XgHnbM
CxqQaMv2rTZLExhUJad9g7/VVA4QeF7dYy4hMOCeGvyCgjpDSilcrIXFhDMpGTHv
G2RwnFv0QdCRKigqUlMqDeyDPMN85k2uuIlwx9S1LhdVH+kQlS8tJL+clrs8Wl6y
DF6MtH7xFzggkxCduJGxio45RzmU5cHAyixBpLy8zYZ/+cLBCQYrz1dkZgNfuxUG
5IdLJq7FGjkhTR4gRkO2TRRvTGygcY56RhEYVEbxqODGIZBiRrJvjjEG7sMWXe7F
UEiEMPE8BhljqB/7EF1/67LLMyzTkS4zUIsRxVjbRgprK7Pi2d+TCaMC4KZfhA+u
/5vqNPH5YDynS8xvr22qT2/gWtb+tzo42NF1bEmLLYfMZxqCP6a3hksptQARAQAB
tClTZWJhc3RpYW4gR2FiYmVydCA8Z2l0aHViQGh1ZWhuZXJob3NlLmRlPokCTgQT
AQgAOBYhBKA/q+MVd7BNt95Mg9bnqTVR7sweBQJZ/t2NAhsDBQsJCAcCBhUICQoL
AgQWAgMBAh4BAheAAAoJENbnqTVR7swerDsP/iKlnvpOu+ZRvW7jXrf6EvsX7DuN
t57Ygj18HoNafVNzmDBzmpoT5jqsCPN0VlO8JfLo52Ph6UAxm4cy/NE4Wl3Lj+Tp
KxIgfEzJz2f4qaQ2iPGWMVQTSKyFk4fDJsNVxhm7FMFbfgUNXgRicR2cFZ7HFSrc
DjDtrgsgjYKEgBXa4sqOqLgLo9FS074mY5SB7Km4lshwLu30triPKT34z3zoZHC1
Kw+f4Ev+Tua3Zg1n1LBHmSA7UNKY6P7lQwJKnhLMV5F/VWfVA4dTF5mXLtql+BBk
tRmxCMvKzhIauCNwhVs/m4EgEc8BDCimyBdqODj6u/IrV68ZmFnkXhvduk+zIpCt
IBidcV4u8Hpuqqm4ZDDBtVcnyXrpEkAzlETx7xnztSB0S2henaBmqiNZmbddfBU2
uK6EY/L2XIxR4FFQXKvx1z9N0ef05XsZLIMv/9/QfkY0tcqzLc+aQCng/o5va13u
Xa60hkfrl3Yr44MvxRLoIJ74JX0zwHoFAfZVrgIEPIIyPVPz/XnZ0vfsbOoeWaf8
V8TbuYIYBTktTYy7s93LhtEsNOpzqMKloBRrWAAVI0+ZmbxzSlhX1+E4Iu9qVrJu
lFHyrulcaArjIVKspJITH60f0fgH36kVmQ6dvPmKwW+zXEvKmCWCBOpbKFyYX4MT
5vs61wkg07IPjSE8tCZTZWJhc3RpYW4gR2FiYmVydCA8Z2l0QGh1ZWhuZXJob3Nl
LmRlPokCTgQTAQgAOBYhBKA/q+MVd7BNt95Mg9bnqTVR7sweBQJZ/t5iAhsDBQsJ
CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJENbnqTVR7sweNpkQAKHsTyq4mwiKizAR
z8QBz3U17wSWn96cBIrCyq0JZ5h1v/OiW3j/Ke/QOxvTXB9ZK4cOeVS7KdR1rHTI
byVgY0q81wyIaL8DRHcxpXn3RfITiTnMK0pBgiiUiFeW6XNo8bQZxI0p6cxvrRlL
8moOZaGSZ7uwsa36kfVXY1HUGhue5qugfO11m6Q0V9uwAj8mSvJ1M6iTLIuXBlIQ
E9/OojoMD7EQbOMow8vn5RWkpb/BWVpdhf7wIB4ayeR2YW4/fsAMqZX22KcyXIWY
moyMKtxVJtzyxbomL50zmTevAeOOdsm4Rh0sJbR6sORxAiqD46O0c35rNaAqyBrT
gEpYAaSgag30iADt4FOe7VMl6yxThIsVj7o49e4R1wGIbnuxOLSI5v8Ux5CbcMz8
64XaKxSEu81t9IL9gqFhUcRejkrsOzMFiPlliWxDd3PnP09BoD0wA5n4xa0xj69D
loVLU/KFQDARniFH1RGYULV59VbNo9odA70eE6AeJWqZgnlIzyi7qe6wN1LzhGis
cq/nUrI2qr4WqyiZfs5/JrnfiXdszLu5vxB0uDSupP30jTnkke3wnYuL5VKp7K0Z
QqZQOspcj0E1yXm6VsEbjTe/ZG1g+kKTVmW48y6F/DVBYr+V/VWZxDkoZU4FXvl8
eAPh0QlMUVNP+JuVuz7zTY6L12rztCxTZWJhc3RpYW4gR2FiYmVydCA8c2ViYXN0
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
=2HNJ
-----END PGP PUBLIC KEY BLOCK-----`

const qwertPrivate = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
6nRR466ipFStt9QTxQa8M9wTYg==
=Z2Y8
-----END PGP PRIVATE KEY BLOCK-----`

const pass = "qwert123"

// OLD

func TestRetrievePubKeysFromDB(t *testing.T) {
	_, mock, err := database.NewMock()
	if err != nil {
		log.Fatal(err)
	}

	recipients := []string{"testa@gmx.de", "testb@gmail.com", "testc@mail.ru"}

	var rows [3]*sqlmock.Rows
	rows[0] = sqlmock.NewRows([]string{"pgpKey"}).AddRow("---PGP MESSAGE--- herp ---PGP MESSAGE---")
	rows[1] = sqlmock.NewRows([]string{"pgpKey"}).AddRow("---PGP MESSAGE--- derp ---PGP MESSAGE---")
	rows[2] = sqlmock.NewRows([]string{"pgpKey"}).AddRow("---PGP MESSAGE--- serp ---PGP MESSAGE---")

	mock.ExpectBegin()

	for i := 0; i < len(recipients); i++ {
		mock.ExpectQuery("^SELECT pgpKey FROM employeeapp.keysPGP WHERE recipient=(.+)").WithArgs(recipients[i]).WillReturnRows(rows[i])
	}

	mock.ExpectCommit()

	res, err := retrievePubKeysFromDB(recipients)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, len(res), 3)
	assert.Equal(t, "---PGP MESSAGE--- herp ---PGP MESSAGE---", res[0])
	assert.Equal(t, "---PGP MESSAGE--- derp ---PGP MESSAGE---", res[1])
	assert.Equal(t, "---PGP MESSAGE--- serp ---PGP MESSAGE---", res[2])
}

// This test probably needs more love, since at this point in time, it is only tested if the number of the entities equals the number of the public keys
func TestPreparePGPEntities(t *testing.T) {
	pubKeys := []string{qwertPub, qwertPub}

	entities, err := preparePGPEntities(pubKeys)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, len(entities), len(pubKeys))
}

// Decrypt takes an armored (human readable) message which is later decoded
func Decrypt(encryptedMsg string) (string, error) {
	entity, err := getEntity(qwertPrivate)
	if err != nil {
		return "", err
	}

	err = entity.PrivateKey.Decrypt([]byte(pass))
	if err != nil {
		return "", err
	}

	for _, subkey := range entity.Subkeys {
		err = subkey.PrivateKey.Decrypt([]byte(pass))
		if err != nil {
			return "", err
		}
	}

	el := openpgp.EntityList{entity}

	block, err := armor.Decode(bytes.NewBuffer([]byte(encryptedMsg)))
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(block.Body, el, nil, nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return string(bytes), nil

}

// This is verification magic, taken from here: https://github.com/jchavannes/go-pgp/blob/master/pgp/verify.go
func verifySignature(sig []byte) (*packet.Signature, error) {

	sigReader := bytes.NewReader(sig)
	block, err := armor.Decode(sigReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.SignatureType {
		return nil, fmt.Errorf("Not of type openpgp.SignatureType")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	signature, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("Couldnt parse signature")
	}

	return signature, nil
}

func TestSign(t *testing.T) {
	testMessage := "Hello World signed!"

	_, mock, err := database.NewMock()
	if err != nil {
		t.Error(err)
	}

	var rows [1]*sqlmock.Rows
	rows[0] = sqlmock.NewRows([]string{"pgpKey"}).AddRow(qwertPrivate)
	mock.ExpectQuery("^SELECT private FROM employeeapp.crypto_keys WHERE id=(.+)").WithArgs("qwert@mail.xy").WillReturnRows(rows[0])

	signature, err := SigPGP([]byte(testMessage), "qwert@mail.xy", pass)
	if err != nil {
		log.Fatal(err)
	}

	publicQwertEnt, err := getEntity(qwertPub)
	if err != nil {
		log.Fatal(err)
	}

	sig, err := verifySignature(signature)
	if err != nil {
		log.Fatal(err)
	}
	hash := sig.Hash.New()
	messageReader := bytes.NewReader([]byte(testMessage))
	io.Copy(hash, messageReader)

	publicQwertEnt.PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		log.Fatal(err)
	}

}

func TestEncrypt(t *testing.T) {

	message := "Hello World!"
	recipients := []string{"qwert@mail.xy"}

	_, mock, err := database.NewMock()
	if err != nil {
		log.Fatal(err)
	}

	var rows [1]*sqlmock.Rows
	rows[0] = sqlmock.NewRows([]string{"pgpKey"}).AddRow(qwertPub)

	mock.ExpectBegin()

	for i := 0; i < len(recipients); i++ {
		mock.ExpectQuery("^SELECT pgpKey FROM employeeapp.keysPGP WHERE recipient=(.+)").WithArgs(recipients[i]).WillReturnRows(rows[i])
	}

	mock.ExpectCommit()
	encMsg, err := OldEncrypt([]byte(message), recipients)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := Decrypt(encMsg)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, message, decrypted)

}

type f string

func (f *f) WriteTo(writer io.Writer) (int64, error) {
	a := []byte(*f)
	n, err := writer.Write(a)
	return int64(n), err
}

func Test_Encrypt(t *testing.T) {
	// to := []string{"sebastian.gabbert@insitu.de"}
	//
	// // var testString f
	// // testString = "test"
	// //
	// //
	// // e, _ := Encrypt(&testString, to, mockPublicProvider)
	// // e.WriteTo(os.Stdout)
	// // return
	// //
	// //
	// //
	//
	// from := "sender@sender.de"
	//
	// pgpWriter := MailWriter{
	// 	KeyProvider: mockPublicProvider,
	// 	To:          to,
	// }
	//
	// secretMail := mail.NewMessage()
	// secretMail.SetHeader("To", to...)
	// secretMail.SetHeader("From", from)
	// secretMail.SetHeader("Subject", "my secret mail subject")
	// secretMail.SetBody("text/plain", "my darkest secret is *#12!4//(+")
	// secretMail.SetEncrypted(
	// 	"application/pgp-encrypted",
	// 	"application/octet-stream",
	// 	"Version: 1",
	// 	&pgpWriter,
	// )
	//
	// secretMail.WriteTo(os.Stdout)
}
