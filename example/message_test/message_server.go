package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"math/big"
)

const addr = "localhost:4243"

func main() {
	message, err := recv_message()
	if err != nil {
		panic(err)
	}
	fmt.Println(message)
}

func recv_message() (string, error) {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		fmt.Println(err)
	}
	sess, err := listener.Accept(context.Background())
	if err != nil {
		fmt.Println(err)
	}
	var messageBuf []byte
	messageBuf, err = sess.ReceiveMessage()
	return string(messageBuf), err
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
