// keys.go - Generating public/private key pairs.
package multisig

import (
	"github.com/prettymuchbryce/hellobitcoin/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"fmt"
	"log"
)

type NetParams struct {
	A, B , Name string
}

type BytesProvider interface {
	Provide() []byte
}

type GeneratedPrivateKeyProvider struct {}

type PrivateKeyProvider struct {
	Key string
}

func (GeneratedPrivateKeyProvider) Provide() []byte {
	return btcutils.NewPrivateKey()
}

func (provider PrivateKeyProvider) Provide() []byte  {
	result , err := hex.DecodeString(provider.Key)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

type KeysConfig struct {
	NetParams NetParams
	Provider *BytesProvider
	FlagKeyCount int
	FlagConcise bool

}

//OutputKeys formats and prints relevant outputs to the user.
func OutputKeys(config KeysConfig) {
	if config.FlagKeyCount < 1 || config.FlagKeyCount > 100 {
		log.Fatal("--count <count> must be between 1 and 100")
	}

	if !config.FlagConcise {
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("Disclaimer: These key pairs are cryptographically secure to the limits of the crypto/rand cryptography package in Golang. They should not be used without further security audit in production systems.")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("Each generated key pair includes: ")
		fmt.Println("* Your private key\t\t\t-- Keep this private, needed to spend received Bitcoins.")
		fmt.Println("* Your public key\t\t\t-- in HEX format. This is required to generate multisig destination address.")
		fmt.Println("* Your public destination address\t-- Give this to other people to send you Bitcoins.")
		fmt.Println("----------------------------------------------------------------------")
	}

	privateKeys, privateKeyWIFs, publicKeyHexs, publicAddresses := generateKeys(config)

	for i := 0; i <= config.FlagKeyCount-1; i++ {

		fmt.Println("-------------------------------------------------------------")
		fmt.Printf("%s: KEY #%d\n", config.NetParams.Name, i+1)
		if !config.FlagConcise {
			fmt.Println("")
		}
		fmt.Println("Private key: ")
		fmt.Println(privateKeys[i])
		if !config.FlagConcise {
			fmt.Println("")
		}
		fmt.Println("Private key WIF: ")
		fmt.Println(privateKeyWIFs[i])
		if !config.FlagConcise {
			fmt.Println("")
		}
		fmt.Println("Public key hex: ")
		fmt.Println(publicKeyHexs[i])
		if !config.FlagConcise {
			fmt.Println("")
		}
		fmt.Println("Public Bitcoin address: ")
		fmt.Println(publicAddresses[i])
		fmt.Println("-------------------------------------------------------------")
	}
}

// generateKeys is the high-level logic for generating public/private key pairs with the 'go-bitcoin-multisig keys' subcommand.
// Takes flagCount (desired number of key pairs) and flagConcise (true hides warnings and helpful messages for conciseness)
// as arguments.
func generateKeys(config KeysConfig) ([]string, []string, []string, []string) {
	publicKeyHexs := make([]string, config.FlagKeyCount)
	publicAddresses := make([]string, config.FlagKeyCount)
	privateKeys := make([]string, config.FlagKeyCount)
	privateKeyWIFs := make([]string, config.FlagKeyCount)

	for i := 0; i <= config.FlagKeyCount-1; i++ {
		//Generate private key
		privateKey := (*config.Provider).Provide()
		//Generate public key from private key
		publicKey, err := btcutils.NewPublicKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		//Get hex encoded version of public key
		publicKeyHexs[i] = hex.EncodeToString(publicKey)
		//Get public address by hashing with SHA256 and RIPEMD160 and base58 encoding with mainnet prefix 00
		publicKeyHash, err := btcutils.Hash160(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		publicAddresses[i] = base58check.Encode(config.NetParams.A, publicKeyHash)
		//Get private key in Wallet Import Format (WIF) by base58 encoding with prefix 80
		privateKeyWIFs[i] = base58check.Encode(config.NetParams.B, privateKey)
		privateKeys[i] = hex.EncodeToString(privateKey)
	}

	return privateKeys, privateKeyWIFs, publicKeyHexs, publicAddresses
}
