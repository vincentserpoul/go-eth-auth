package goethauth

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// IsChallengeSignedByEthAccount returns true or false according to
// if the sig matches the challenge
func IsChallengeSignedByEthAccount(
	ethAccountStr string,
	challenge string,
	sigStr string,
) (bool, error) {
	ethAccount := common.BytesToAddress(common.FromHex(ethAccountStr))
	// Decode signature into bytes
	sig := common.FromHex(sigStr)

	sig = CleanSig(sig)

	// Get the publicKey
	pubkey, errPub := crypto.SigToPub(HashEthereumString(challenge), sig)
	if errPub != nil {
		if errPub != nil {
			return false,
				fmt.Errorf(
					"IsChallengeSignedByEthAccount: err extracting pubkey (%v)\n"+
						"Hashed challenge: 0x%x\n"+
						"Sig: 0x%x\n",
					errPub,
					HashEthereumString(challenge),
					sig,
				)
		}
	}

	signedEthAccount := crypto.PubkeyToAddress(*pubkey)

	if signedEthAccount != ethAccount {
		return false,
			fmt.Errorf(
				"IsChallengeSignedByEthAccount: signed by EthAccount %s "+
					"but used to login "+
					" for EthAccount %s",
				signedEthAccount.String(), ethAccount.String())
	}

	return true, nil

}

// HashEthereumString is how you hash messages in Ethereum
func HashEthereumString(challenge string) []byte {
	return crypto.Keccak256(
		[]byte(
			"\u0019Ethereum Signed Message:\n" +
				strconv.Itoa(len(challenge)) +
				challenge,
		),
	)
}

// CleanSig like go-ethereum does
// The V value of the ECDSA is either 27 (1B) or 28 (1C)
// but go-ethereum wants that to be either 00 or 01
func CleanSig(sigB []byte) []byte {
	if len(sigB) == 0 {
		return sigB
	}
	if bytes.HasSuffix(sigB, []byte{0x1b}) {
		return append(sigB[:len(sigB)-1], 0x00)
	}
	if bytes.HasSuffix(sigB, []byte{0x1c}) {
		return append(sigB[:len(sigB)-1], 0x01)
	}

	return sigB
}
