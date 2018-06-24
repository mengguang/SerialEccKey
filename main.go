package main

import (
	"github.com/tarm/serial"
	"log"
	"math/big"
	"crypto/elliptic"
	"crypto/ecdsa"
	"fmt"
	"time"
	"crypto/rand"
	"crypto/sha256"
)

const MagicBegin = 0x88
const MagicEnd = 0x99

const ProtocolVersion = 0x01
const ProtocolResultSuccess = 0x00

const ProtocolBufferSize = 96
const MagicBeginPos = 0
const MagicEndPos = 95

const ProtocolVersionPos = 1
const ProtocolOpcodePos = 2
const ProtocolParam1Pos = 3
//const ProtocolParam2Pos = 4
const ProtocolDataPos = 6

const ProtocolResultCodePos = 2
const ProtocolResultDataPos = 3

type NewKey struct  {
	Port *serial.Port
	Name string
	Baud int
}

func (p *NewKey) OpenPort() error {
	c := &serial.Config{Name: p.Name, Baud: p.Baud, ReadTimeout: time.Millisecond * 200}
	s, err := serial.OpenPort(c)
	if err != nil {
		return err
	}
	p.Port = s
	return nil
}
func (p *NewKey) writeRequest(request [ProtocolBufferSize]byte) error {
	n, err := p.Port.Write(request[:])
	if err != nil {
		return err
	}
	if n != ProtocolBufferSize {
		return fmt.Errorf("write %v bytes not equal to %v",n,ProtocolBufferSize)
	}
	return nil
}

func (p *NewKey) readReply() ([ProtocolBufferSize]byte, error) {
	nRead := 0
	retry := 0
	var reply [ProtocolBufferSize]byte
	for {
		n, err := p.Port.Read(reply[nRead:])
		if err != nil {
			return reply,err
		}
		if n == 0 {
			retry++
			if retry > 5 {
				err = fmt.Errorf("read retry too many times, abort")
				return reply,err
			}
		}
		//fmt.Printf("read %v\n", n)
		nRead += n
		if nRead == ProtocolBufferSize {
			return reply,nil
		}
	}
}

func (p *NewKey) Verify(bytePubKey []byte, byteData []byte, byteSignature []byte) bool {
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

func (p *NewKey) ChangePassword(oldPassword [32]byte, newPassword [32]byte) error {
	var request [ProtocolBufferSize]byte
	request[MagicBeginPos] = MagicBegin
	request[ProtocolVersionPos] = ProtocolVersion
	request[ProtocolOpcodePos] = 0x12

	copy(request[ProtocolDataPos:],oldPassword[:])
	copy(request[ProtocolDataPos+32:],newPassword[:])

	request[MagicEndPos] = MagicEnd

	err := p.writeRequest(request)
	if err != nil {
		return err
	}
	reply, err := p.readReply()
	if err != nil {
		return err
	}

	result := reply[ProtocolResultCodePos]
	if result != ProtocolResultSuccess {
		return fmt.Errorf("operation failed: %v",result)
	}
	return nil
}

func (p *NewKey) WritePrivateKey(password [32]byte, privateKey [32]byte) error {
	var request [ProtocolBufferSize]byte
	request[MagicBeginPos] = MagicBegin
	request[ProtocolVersionPos] = ProtocolVersion
	request[ProtocolOpcodePos] = 0x46

	copy(request[ProtocolDataPos:],password[:])
	copy(request[ProtocolDataPos+32:],privateKey[:])

	request[MagicEndPos] = MagicEnd

	err := p.writeRequest(request)
	if err != nil {
		return err
	}
	reply, err := p.readReply()
	if err != nil {
		return err
	}

	result := reply[ProtocolResultCodePos]
	if result != ProtocolResultSuccess {
		return fmt.Errorf("operation failed: %v",result)
	}
	return nil
}

func (p *NewKey) GetPublicKey(password [32]byte) ([64]byte, error) {
	var request [ProtocolBufferSize]byte
	request[MagicBeginPos] = MagicBegin
	request[ProtocolVersionPos] = ProtocolVersion
	request[ProtocolOpcodePos] = 0x40

	copy(request[ProtocolDataPos:],password[:])

	request[MagicEndPos] = MagicEnd

	var resultData [64]byte

	err := p.writeRequest(request)
	if err != nil {
		return resultData,err
	}
	reply, err := p.readReply()
	if err != nil {
		return resultData,err
	}
	result := reply[ProtocolResultCodePos]
	if result != ProtocolResultSuccess {
		return resultData,fmt.Errorf("operation failed: %v",result)
	}
	copy(resultData[:],reply[ProtocolResultDataPos:])
	return resultData,nil
}

func (p *NewKey) SignData(password [32]byte, data[32]byte) ([64]byte, error) {
	var request [ProtocolBufferSize]byte
	request[MagicBeginPos] = MagicBegin
	request[ProtocolVersionPos] = ProtocolVersion
	request[ProtocolOpcodePos] = 0x41
	request[ProtocolParam1Pos] = 0x80

	copy(request[ProtocolDataPos:],password[:])
	copy(request[ProtocolDataPos+32:],data[:])

	request[MagicEndPos] = MagicEnd

	var resultData [64]byte

	err := p.writeRequest(request)
	if err != nil {
		return resultData,err
	}
	reply, err := p.readReply()
	if err != nil {
		return resultData,err
	}
	result := reply[ProtocolResultCodePos]
	if result != ProtocolResultSuccess {
		return resultData,fmt.Errorf("operation failed: %v",result)
	}
	copy(resultData[:],reply[ProtocolResultDataPos:])
	return resultData,nil
}

func main() {
	newkey := NewKey{Name: "COM6", Baud: 115200}
	err := newkey.OpenPort()
	if err != nil {
		log.Fatal(err)
	}

	var password [32]byte
	copy(password[:],"88888888888888888888888888888888")

	err = newkey.ChangePassword(password,password)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("ChangePassword successed.")
	}

	privateKey,err := ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err != nil {
		fmt.Printf("GenerateKey error: %v",err)
	}
	pubKey := privateKey.PublicKey
	fmt.Printf("private key:\n%X\n", privateKey.D)
	fmt.Printf("public key:\n%X\t%X\n",pubKey.X,pubKey.Y)

	var rawPrivateKey [32]byte
	copy(rawPrivateKey[:], privateKey.D.Bytes())

	err = newkey.WritePrivateKey(password,rawPrivateKey)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("WritePrivateKey successed.")
	}

	rawPublicKey, err := newkey.GetPublicKey(password)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("GetPublicKey successed.")
	}

	x := big.Int{}
	y := big.Int{}
	keyLen := len(rawPublicKey)
	x.SetBytes(rawPublicKey[:(keyLen / 2)])
	y.SetBytes(rawPublicKey[(keyLen / 2):])

	fmt.Printf("public key:\n%X\t%X\n",&x,&y)
	if x.Cmp(pubKey.X) == 0 && y.Cmp(pubKey.Y) == 0  {
		fmt.Println("public key is ok.")
	} else {
		fmt.Println("public key is wrong.")
	}

	hash := sha256.Sum256(password[:])
	sign, err := newkey.SignData(password,hash)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("SignData successed.")
	}
	//fmt.Printf("SignData:\n%X\n",sign)
	signResult := newkey.Verify(rawPublicKey[:],hash[:],sign[:])
	fmt.Printf("verify result: %v",signResult)

}
