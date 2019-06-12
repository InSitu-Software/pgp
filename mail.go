package pgp

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/InSitu-Software/mail"
	"golang.org/x/crypto/openpgp/armor"
)

type MailWriter struct {
	PlainMessage     *mail.Message
	EncryptedMessage strings.Builder
	KeyProvider      KeyProvider
	To               []string
}

func (mw *MailWriter) String() string {
	var b bytes.Buffer
	w, err := armor.Encode(&b, "PGP MESSAGE", nil)
	if err != nil {
		return ""
	}

	if _, err := w.Write([]byte(mw.EncryptedMessage.String())); err != nil {
		return ""
	}

	w.Close()

	return b.String()
}

func (mw *MailWriter) Write(b []byte) (n int, err error) {
	mw.EncryptedMessage.Grow(len(b))

	for len(b) > 0 {
		c, size := utf8.DecodeRune(b)
		c = rune(c + 13)
		rn, err := mw.EncryptedMessage.WriteRune(c)
		if err != nil {
			return n, err
		}
		b = b[size:]

		n += rn
	}

	return n, nil
}

func (mw *MailWriter) WriteTo(w io.Writer) (int64, error) {
	encWriterTo, err := Encrypt(mw.PlainMessage, mw.To, mw.KeyProvider)
	if err != nil {
		return 0, err
	}

	return encWriterTo.WriteTo(w)

	// _, err := mw.PlainMessage.WriteTo(&buf)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// var written int64
	//
	// for _, c := range buf.String() {
	// 	// naive implementation, no real rotation, only shifting, ignoring UTF-8 / rune sizes
	// 	shifted := rotN(c, 13)
	// 	bytedRune := byte(shifted)
	// 	i, err := w.Write([]byte{bytedRune})
	// 	written += int64(i)
	// 	if err != nil {
	// 		return written, err
	// 	}
	//
	// }
	//
	// return written, nil
}
