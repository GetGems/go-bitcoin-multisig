package multisig

import (
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"testing"
	"github.com/soroushjp/go-bitcoin-multisig/testutils"
)

func TestGenerateKeys(t *testing.T) {

	var provider BytesProvider = GeneratedPrivateKeyProvider{}
	keysConfig := KeysConfig{btcutils.MainNet, &provider, 1, false}

	privateKeys, privateKeyWIFs, publicKeyHexs, publicAddresses := generateKeys(keysConfig)
	publicKey, err := hex.DecodeString(publicKeyHexs[0])
	if err != nil {
		t.Error(err)
	}
	err = btcutils.CheckPublicKeyIsValid(publicKey)
	if err != nil {
		t.Error(err)
	}
	if privateKeys[0] == "" {
		t.Error("Generated private key cannot be empty.")
	}
	if privateKeyWIFs[0] == "" {
		t.Error("Generated private key cannot be empty.")
	}
	if len(privateKeyWIFs[0]) != 51 {
		t.Error("Generated private key is wrong length. Should be 51 characters long.")
	}
	if privateKeyWIFs[0][0:1] != "5" {
		t.Error("Generated private key has wrong prefix. Should be '5' for mainnet private key.")
	}
	//Testing for publicAddress could be made more robust in future by checking SHA256 checksum matches address.
	if publicAddresses[0] == "" {
		t.Error("Generated public address cannot be empty.")
	}
	if len(publicAddresses[0]) < 26 || len(publicAddresses[0]) > 34 {
		t.Error("Generated public address is wrong length. Should be betweeen 26 and 34 characters.")
	}
	if publicAddresses[0][0:1] != "1" {
		t.Error("Generated public address has wrong prefix. Should be '5' for mainnet P2PKH addresses.")
	}
}

var flagtests = []struct {
	seed string
	privateKeyWIF string
	publicKeyHex string
	publicAddress string
} {
	{"f97ce45c397fc5e789a80f9fef2e48ea467cd849e9b19e3fdb534930e5096f32",
	"93UnzhspvmuUTsYjTCbYccLwdouR9yV38xNe9F9g3NSS34Gh8SW",
	"041ceb8a73d7b7e5d8cbd6fa09d6213165a34530c3eaddaa56632ace57c8207a8d51d644cb39b6bd59bdf33dd1ac7aae85d803df93dd2afb8b0183699fb4bca71d",
	"mtzFS2QEeDxqTq4XMQetPebi83KKFwBE6B"},
}


func TestGenerateKeys_f97ce45c397fc5e789a80f9fef2e48ea467cd849e9b19e3fdb534930e5096f32(t *testing.T) {

	for _, tt := range flagtests {
		var provider BytesProvider = PrivateKeyProvider{tt.seed}
		keysConfig := KeysConfig{btcutils.TestNet, &provider, 1, false}
		privateKeys, privateKeyWIFs, publicKeyHexs, publicAddresses := generateKeys(keysConfig)

		testutils.Assert(t, privateKeys[0] == tt.seed, "PrivateKey doesn't match (%s - %s)", privateKeys[0], tt.seed)
		testutils.Assert(t, privateKeyWIFs[0] == tt.privateKeyWIF, "PrivateKeyWif doesn't match (%s - %s)", privateKeyWIFs[0], tt.privateKeyWIF)
		testutils.Assert(t, publicKeyHexs[0] == tt.publicKeyHex, "Public Key doesn't match (%s - %s)", publicKeyHexs[0], tt.publicKeyHex)
		testutils.Assert(t, publicAddresses[0] == tt.publicAddress, "Public address doesn't match (%s - %s)", publicAddresses[0], tt.publicAddress)
	}
}


