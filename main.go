package main

import (
	"github.com/tarm/serial"
	"log"
	"math/big"
	"crypto/elliptic"
	"crypto/ecdsa"
	"golang.org/x/crypto/sha3"
	"fmt"
	"time"
)

const magicBegin byte = 0x88
const magicEnd byte = 0x99

func Verify(bytePubKey []byte, byteData []byte, byteSignature []byte) bool {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(byteSignature)
	r.SetBytes(byteSignature[:(sigLen / 2)])
	s.SetBytes(byteSignature[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(bytePubKey)
	x.SetBytes(bytePubKey[:(keyLen / 2)])
	y.SetBytes(bytePubKey[(keyLen / 2):])

	curve := elliptic.P256()
	realPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&realPubKey, byteData, &r, &s) == false {
		return false
	} else {
		return true
	}
}

func main() {
	c := &serial.Config{Name: "COM3", Baud: 115200,ReadTimeout: time.Millisecond * 200}
	s, err := serial.OpenPort(c)
	if err != nil {
		log.Fatal(err)
	}

	getPubKeyRequest := make([]byte,64)
	getPubKeyRequest[0] = magicBegin
	getPubKeyRequest[1] = 0x06 //length
	getPubKeyRequest[2] = 0x40 //opcode
	getPubKeyRequest[3] = 0x00 //param1
	getPubKeyRequest[4] = 0x00 //param2
	getPubKeyRequest[5] = 0x00 //param2
	getPubKeyRequest[6] = magicEnd

	n, err := s.Write(getPubKeyRequest)
	if err != nil {
		log.Fatal(err)
	}
	nRead := 0
	retry := 0
	getPubKeyReply := make([]byte,96)
	for {
		n, err = s.Read(getPubKeyReply[nRead:])
		if err != nil {
			log.Fatal(err)
		}
		if n == 0 {
			retry++
			if retry > 5 {
				fmt.Println("read retry too many times, abort.")
				return
			}
		}
		fmt.Printf("read %v\n",n)
		nRead += n
		if nRead == 96 {
			break
		}
	}

	//log.Printf("read %d bytes.\n",nRead)
	pubKey := getPubKeyReply[2:66]
	fmt.Printf("public key:\t %x\n", pubKey)

	textData := "Hello, World!"
	hashData := sha3.Sum256([]byte(textData))
	fmt.Printf("hash data:\t %x\n",hashData)

	signRequest := make([]byte,64)
	signRequest[0] = magicBegin
	signRequest[1] = 0x26	//length
	signRequest[2] = 0x41	//opcode
	signRequest[3] = 0x80	//param1
	copy(signRequest[6:],hashData[:])
	signRequest[38] = magicEnd

	n, err = s.Write(signRequest)
	//fmt.Printf("signRequest: %v\n",signRequest)
	if err != nil {
		log.Fatal(err)
	}
	nRead = 0
	retry = 0
	signReply := make([]byte,96)
	for {
		n, err = s.Read(signReply[nRead:])
		if err != nil {
			log.Fatal(err)
		}
		if n == 0 {
			retry++
			if retry > 5 {
				fmt.Println("read retry too many times, abort.")
				return
			}
		}
		nRead += n
		if nRead == 96 {
			break
		}
	}

	//fmt.Printf("read %d bytes.\n",nRead)
	sign := signReply[2:66]
	fmt.Printf("signature:\t %x\n", sign)
	//fmt.Printf("%v", signReply)

	result := Verify(pubKey,hashData[:],sign)
	fmt.Printf("verify result:\t %v",result)

}
