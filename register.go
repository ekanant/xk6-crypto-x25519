package crypto_x25519

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/crypto-x25519", new(K6X25519))
}

type K6X25519 struct{}

// Generate X25519 keypair
func (K6X25519) GenerateKeyPair() map[string][]byte {
	var priv [32]byte
	_, err := rand.Read(priv[:])
	if err != nil {
		panic(err)
	}

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return map[string][]byte{
		"privateKey": priv[:],
		"publicKey":  pub[:],
	}
}
