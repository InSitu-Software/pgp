package pgp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const qwertPub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
Yg==
=/Ahu
-----END PGP PUBLIC KEY BLOCK-----`

const qwertPrivate = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQWGBFyTpCUBDADEu8vCHdZTcBQfgUZms+9jQBz9gvvq2s2L560jRVR7tHDGEdPY
5SMZzxHIpmYIL8xKcntIvaMLIgzyhyxrPOfMNs5atQ6Y7ovgW/E9RjQOyaPCxG6D
eFDHThQFsyHvsQaTF8jWfWaB//AXQl7gfrY0mGsrRbxS/w8ycA9wpvQugdl3aMiX
RpxJwrF/jTisgSBdQUds6Robj8fXmU41n5hnJEQUe03/260bXvaVexBwObGyf6Jq
GF/AAHToT/FoJtqI646f3rUuko2VrYarmv98LMzWBFDx7J428UVRaIaFHYd4mRdA
qlXwAwIi20CBa9YBByyENr4wsI0yI/HTeaQayIxCb4S+k3XZTSvAum2K48xin0TF
6ne7Qa+y+wzQMq2QHVJbhBWK1QJcFTmVya69/1dKMzbMn7wtcAMRIS0bi2PjJYeC
xxZsTxs+/4kifLNvkxjYMIfWsgx64fOzwN5JEYnVj1rREbjMKj+19vOrYsi3MkKL
jKtY50vR84BpDWUAEQEAAf4HAwLo2osPzkAjY/+BjsnvVyGht401n9tgXH3oR0qM
S2IZMmwg5P6PoolEO/N3gwnPA7yawF/JJC3HwlxadbqZVEI7UdQX33+oMhKf9dua
FU1y8goUfTnAJYhopvyyb4dduZXWUeWJrxMCXQ/ti2gb8NoIMG5NlRyYYrvh+p4Q
xpJ1EzpPG2oUhb6/cltvTAPgeDqhb6uMT4WBFTj3kJwn2Dt37BxVzMCfv+WmdRdp
xRsx9oh6PJEU1fiRFZEQXf0wgdO2RfoSCUFE2SKn2aXtmn0VUPshvP0g/zTQJuse
DVNjfHiZkmDsMlV35do9HpqNeTrdTYc1mgRLeJAP/PMU3QIXjllaqj9MKORBlvFI
pP3Y+PVSKkozqa2vDk6DCDJruob5a0m2HTYdCz2qKU3UWCnwMylJphhYC2RHRqZh
+iq+H1P6XnIFT+WJlAxX9eryRtDDrNLc9BaSFvqN1RcNNiVj1mnWb8JjuIgv3DUe
PrIlJxJwI0+qx9cSL0Zm+ve9cI6sKVx1hJ/WlMIkByttK56pe+NUq1n+jsDalXPl
oGJelhK4ZY+aBQyNWheUwKfIFqCL1q6ighLvqt7JByQ7djr9ea0poWGhwYci40Ix
jPHV/1dLjWuSjjDgZP5eoJwwl+sWwdTQ1CR2n7VQ6ynAEL15P3LnjXqCwgAnQTDH
Lzjzzb+c1z3NvHJpAxUoBKilSLUWaNjcfNL26DC9manqxUEBnKM8Gk65Dry/NSd4
9TlbC9BeyCPkmcckKhtzckgoUV3cYN6Km4vtFo9umjWuD4NTXBhMNMWLSnxM3+x4
mCf4Ags9lgiTJuE3pxXvbyub6fqGnhVy4YAMEUfRfqXfUjOyJjE/FKGKnRTwr/I6
MvFNG+vwTvM6guGBQtvIKK9PJZzIvTe/rdwX53P5pugSzevx10qmxjdbBlkIQTUU
2yDvc8rIe435lNvSnvpWtXKgCG8w7xJaXsFZjIdqWXQczuBpurG9PdXgn/d4Bcyc
j4AFJW88naOFrz5f9A3EbxxtpT4UUu8YrTvrmEs/uzdfZaE2d8Pp8UJWivZnL6Fo
OY8G1N14WSFF3YZL2+uaXLGliW2/XTA0FeYc5jb2MvBDHUmy8R+wNGP/kENxGCnX
EGHw7gx+6bg29eDpDiBwD7vEmtNeoMzgaYYW+Y6yk2KXO9epgiSSzM/yqzHywwJ6
ZR+n8dMxw7m14D9O34R6g9Yv0A1OH9Sg99JSsMYtajc08KeLaUKIvpQgouyGuPWp
tm6W3S0b3IrURcKLhl1tf5KGdL/fZ5N80fyJydOx2u5StDAnSitKMyjaViqlL/Xj
QX+1Oy0123y49xSc6LDewvFcdwvtCY28hLQVcXdlcnQgPHF3ZXJ0QG1haWwueHk+
iQHOBBMBCgA4FiEE4V4JFYerUUeDz3OKH0q5Ouaz9EUFAlyTpCUCGwMFCwkIBwIG
FQoJCAsCBBYCAwECHgECF4AACgkQH0q5Ouaz9EVRjQv+P0CFSYXVp6+sBtRBUAVb
gnZNQQJdfU/yFPn5sTLCCU06L6W0Pubx2RqOOefpqhUEqFZ6hGA/NBO+CtTUYE10
F1NCwO0UnlWYgoMSG5eBXObsZjG/FskfYEPUo7KK64gUveq/sZLjMsR/D09sO8mL
Ay+IPslrebdDSWjNCxtvLZxe8hR6lS4S8ZflGX5PoaYXAebeU5VOEpxWGAoApskT
uKrxZ2aSv6UKMgUNUe44eJ2ntOW/JjismHQkGV5jbcEW/kHgcLUFZ0ShCoUX6FDf
GVZz2oOWnV6Wn5WFSsOhQns5LuuTXui9pDYe9JNfmzIpSpLmj0TzueEnSAiFfHkO
X5huRARupUwIMaTGcAN6oHPHPuzKXmAVEPpLW8UmtvL7C/rHEjxbkC1P2QiJtVOj
xP1zn29/SkBfTy2TkIk7rNmad75DFMGhE62pwq/wQW3oLHKDTx2AMZzEJauz2J81
7GmODHzWzPo5BPs58D67/jMw9U67lqDRwkSlx//0K92tnQWGBFyTpCUBDAC9/sm7
h4n1Eq/erESdMY9VJBsyCDch/Vn3zPnawrwyjwIWfpgEYzcZMbpafdSxeK03+JNi
/Hn+LlrmzYwqB+7XXfqC1a6orOnPy6//3GzlZq5W0xXaTNrCRBJKlGlIi33/fJTw
0NzUiTTODvERXFDjnZDA1m8FpJYYUtIBrXWe0uFSqX5TnXTYjaxqwyH1Mind94rg
X7w7JXK4dtafUk6a42eO4AVyK7NBYKH+F2cQyarUDMMW+7zJYcvwDrs2+ud+PzB6
zMFE+37scBA21Kiu95NyUgdHc4VowX7KVPFjOYsrInaYj7nUOiPrUePOiXfBY5nY
QGdC8ezhFHV7ECJMK8G5OfM4xA9+Ak1lRoOYQd7l/QVYWtNyVDfq0LMpLDPH95pC
Y1Ovn7MKyzU1ls4bZ74EI9GOxSjv4DFYKAWuYWJC+FChBFfD8k2+vcmiLylkXdhY
AL5hBXZeF98dY58c/FK7S78UiAMDntyp/mKJtYSbv/VxVvwDUv8xMYe6CakAEQEA
Af4HAwK6Ce+1Vfac5P9+8MwfH6DPMq9OxiriVGW6d80Z9qCvKzr9nkk8Z1pZoSxE
9jhdYABDqYakNQbfcDQnK6B1DXUz4xS15Kr/oWQi6STNVTO671JeNVFKKxdm0dVY
PxpEMW4BRyeZhD2yFDIEW408Ea5b84riuuy+WxG4ZDk1vSa7M4tTHQDSzWWBU+eB
TaRO2o7CYdBihzmB0AenyAIHEqnSDUe0ns1jl+L+BNz4N0XVekksh+hpdsq1on4v
N+Sctj7rrfiCf0YEBJQ22esp9SJjY94bLmBX0VKMudqj0F7tq7HLZMWazI7j6IGe
nh0dXaCLNdt0ACl3l9hMD5vtTRPdjZIdtMautvaZj0ogyX5hJqOKPsNC0Tg3qkWZ
kJWefAMjh9qgf9B8RQKVBLAAcDh/ODFvuaMHsPepI5Ajt1Nt2JT4I7LDseC3Ruy/
hjnlPfErTESy5w9t6PaI7QSJgPW9Ow8De6UorRWGexrdBQZzj5kzzR9/IQqTL5Ja
8vgB1VCu8BEB+gVeC2rhIvQBpayIoo+irqQY4P3j3oRFv2hk33U4epaPEWQlmmA7
JdBduyBPlvL5wq41wES54Qs7qEu41sHDKjgEGegRCGu873YHXet8OVJa7FKh7h3/
+7Oiak4dp8OyMVEEjWrUlM6cFqNjkj6mewce8pdGwv7bLXhbEQT4NB3Cz6MANKWZ
l6CAcr3ooSqW3V0rMLkzBmwiHprFyd7Hr37Jm37C1WHjgMeHCq7IsIUk9JCJ5Rg9
qTZfxhdWWFa2owGB56O51SiQiG5UE7dANPj6IKS3chcbbMFUZ26BQSfBlWV7d2hR
2CxCGHBAlgjcEfkVscevtsmaMQgCFqsYBAQNVuFWS/U/Z8zK5xOu0ywjj+7lZ7Aj
NkzGFfu5a7EWxtAeoqen5J5xYRJYWqtPlmLrtGnU/vkyVnFDpJ56Dzilnq6h2ILK
gQoX4tj+VIjqCtzvsJ/NkWv5cRmwv0sAvPnEUtgbOl6QtmsQ3iSnhCLDK33LVIs7
zUZvO3BYJHwM8TGNbo8bQ4DOYbuYD9bgD4zqJmi3ZeCgl60Y2ZZSZePjvuKl7rtm
R/kW0R1U8L0qZCNOBUGk2rzceDhT8XLw/gWNrESGlnfR3ppLOva4PWDkgA3I1Ghn
+sj9Tx2UAtnISChCjuF9q2AgAul6pDA2Vxw57w9v70UCHLji5sfq/m1X378kubf8
XleKZvACpl6nRrTZPsat/DBxQhqSHk2cB3iviT4cQJingN9YhuPU368XPEPehCVK
bH0x4owjJxFTB917yf6tOCYKSGtHYhZNBIR2NohV3EbhQjJ/PTxAF/Gj5GYrzgdE
3zsdSK02a0ZSTYkBtgQYAQoAIBYhBOFeCRWHq1FHg89zih9KuTrms/RFBQJck6Ql
AhsMAAoJEB9KuTrms/RFBukMAJZBi48YogQcf35wIjAlDxpJoh19uti718z3QiDF
2vsfxQeQuIWdC8GTpT4f22I3nOqFyG3s22Hjgj/IBz6wcVfBvBM6cVkfNw8X+l3t
jppzZIlXKL2+o7XsfJaZfkTk+R8ec75eRpTllotymwgsTF1O5xuKPTe6WjlCyJzf
mpvROrdPYketPyNe4FIeP0YinF2qewFRAowRVyATib+hyKcZPS8uEB43xwP0eeOm
CUaWPjIdjkYPb3uwNM14534IxjRll1VFEeLWLKZCqVdHIFLMsIanXexyc9jUqrXH
z9ILOdFm2qH3XJKuoObxMCb8o517D2iNjPpaJUcD09LpWeOgRxN+PCNrPyyvDkOy
5CBBZ5hE4tBuKBtD+DIMba2Y09k4+Tjs1tlVnpVLaTizAP7kcJB7Ek/2nBcj0qwO
kshMdYAFhKoilz3bywyX6dgmKBhBHWOZRmai8sGB2Qb2+NfSiSEkCqYpv902TuzO
6nRR466ipFStt9QTxQa8M9wTYg==
=Z2Y8
-----END PGP PRIVATE KEY BLOCK-----`

const pass = "qwert123"
const recipientMail = "qwert@mail.xy"
const senderMail = "qwert@mail.xy"

// Decrypt takes an armored (human readable) message which is later decoded
func Decrypt(encryptedMsg string) (string, error) {

	entity, err := getSingleEntity(recipientMail, mockPublicProvider, "private", nil)
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
func verifySignature(sig io.Reader, publicKey *openpgp.Entity) (*packet.Signature, error) {
	block, err := armor.Decode(sig)
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
	messageWriter := bytes.NewBufferString(testMessage)

	signatureWriter, err := Sign(messageWriter, senderMail, mockPublicProvider, bytes.NewBufferString(pass).Bytes())
	if err != nil {
		t.Error(err)
	}
	var signatureBuffer bytes.Buffer
	if _, err := signatureWriter.WriteTo(&signatureBuffer); err != nil {
		t.Error(err)
	}

	// TODO
}

func TestEncrypt(t *testing.T) {

	recipients := []string{recipientMail}
	msg := "Hello World"
	messageWriter := bytes.NewBufferString(msg)

	encMsgWriter, err := Encrypt(messageWriter, recipients, mockPublicProvider)
	if err != nil {
		log.Fatal(err)
	}

	var encMsgBuffer bytes.Buffer
	if _, err := encMsgWriter.WriteTo(&encMsgBuffer); err != nil {
		t.Error(err)
	}

	decrypted, err := Decrypt(encMsgBuffer.String())
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, msg, decrypted)
}
