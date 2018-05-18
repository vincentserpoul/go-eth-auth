package goethauth

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// IsMsgSignedByEthAccount returns true or false according to
// if the sig matches the msg
func IsMsgSignedByEthAccount(
	ethAccountStr string,
	msg string,
	sigStr string,
) (bool, error) {
	ethAccount := common.BytesToAddress(common.FromHex(ethAccountStr))
	// Decode signature into bytes
	sig := common.FromHex(sigStr)

	sig = CleanSig(sig)

	// Get the publicKey
	pubkey, errPub := crypto.SigToPub(HashEthereumMessage(msg), sig)
	if errPub != nil {
		if errPub != nil {
			return false,
				fmt.Errorf(
					"IsMsgSignedByEthAccount: err extracting pubkey (%v)\n"+
						"Hashed msg: 0x%x\n"+
						"Sig: 0x%x\n",
					errPub,
					HashEthereumMessage(msg),
					sig,
				)
		}
	}

	signedEthAccount := crypto.PubkeyToAddress(*pubkey)

	if signedEthAccount != ethAccount {
		return false,
			fmt.Errorf(
				"IsMsgSignedByEthAccount: signed by EthAccount %s "+
					"but used to login "+
					" for EthAccount %s",
				signedEthAccount.String(), ethAccount.String())
	}

	return true, nil

}

// HashEthereumMessage is how you hash messages in Ethereum
func HashEthereumMessage(msg string) []byte {
	return crypto.Keccak256(
		[]byte(
			"\u0019Ethereum Signed Message:\n" +
				strconv.Itoa(len(msg)) +
				msg,
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
