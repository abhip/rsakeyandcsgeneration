package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {

	// Initially I was thinking just taking input from the user, however wondering what if someone actually provides a large value that causes issues.
	// So we may need to limit the size of the input , so rather than defining it as string , may be array type with specific size.
	// At the time of writing  I am not sure if this the correct way to do, lets try. I do not know now what need to be done to limit the size, I will leave it for now
	// revist later

	var CommonName string

	var Bitsize int

	var Country string

	var Province string

	var Locality string

	var Organization string

	fmt.Println("Welcome, Enter the following information - If you want to use command directly then use openssl req -nodes -newkey rsa:2048 -out example.req -keyout example.key")

	fmt.Println("Provide the common name - This is a string")

	fmt.Scanln(&CommonName)

	fmt.Println("Enter bitsize for rsa - This is the number, usually it is 2048, 4096")

	fmt.Scanln(&Bitsize)

	fmt.Println("Enter country name - Examaple - US")

	fmt.Scanln(&Country)

	fmt.Println("Enter Province / State - Example - California")

	fmt.Scanln(&Province)

	fmt.Println("Enter Locality/City - Example - Sanjose")

	fmt.Scanln(&Locality)

	fmt.Println("Enter Organization - Example - Apple")

	fmt.Scanln(&Organization)

	//func GenerateKey(random io.Reader, bits int) (*PrivateKey, error), thats the reason we using rand.Reader and also there is another function called as
	//func GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*PrivateKey, error) and I noticed that the default nprimes for GenerateKey is two
	// Generally the users seems to not change that

	//Key is generated after this

	privateKey, err := rsa.GenerateKey(rand.Reader, Bitsize)

	if err != nil {
		fmt.Println(err.Error())
		panic("Something bad happen during RSA Generation")
	}

	pkikName := pkix.Name{
		Country:      []string{Country},
		Province:     []string{Province},
		Locality:     []string{Locality},
		Organization: []string{Organization},
		CommonName:   CommonName,
	}

	rawSubj := pkikName.ToRDNSequence()

	asn1Subj, _ := asn1.Marshal(rawSubj)


	certificateRequestTemplate := &x509.CertificateRequest{
		PublicKeyAlgorithm: x509.RSA,
		RawSubject:         asn1Subj,
	}



	csrByte, err := x509.CreateCertificateRequest(rand.Reader, certificateRequestTemplate, privateKey)

	if err != nil {
		fmt.Println(err.Error())
		panic("Something bad happened during CreateCertificateRequest")

	}

	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrByte,
	}

	privateKeyFile, err := os.Create(CommonName + ".key")

	defer privateKeyFile.Close()

	csrFile, err := os.Create(CommonName + ".req")

	defer csrFile.Close()

	err = pem.Encode(privateKeyFile, privateBlock)

	if err != nil {
		fmt.Println(err.Error())
		panic("Something bad happened during Encoding the private key")
	}

	err = pem.Encode(csrFile, csrBlock)

	if err != nil {
		fmt.Println(err.Error())
		panic("Something bad happen during Encoding the CSR file")
	}

}
