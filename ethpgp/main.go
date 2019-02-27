package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	pghkp "github.com/alyakubov/blockpgp"
)

const HELP_USERADDR string = "User's blockchain address (0x..) should be put into the comment field of the certificate after 'blockchain:' statement, for example 'blockchain:0x023df..'"

/*
var gConfigFile string = "./config/ethpgp.conf"

var gConfig struct {
	ContractHash string `json:"contractHash"`
	IPCpath      string `json:"IPCpath"`
	KeyDir       string `json:"keyDir"`
	ContractAddr common.Address
}


type CertAction int

const (
	CERTACT_LOAD   CertAction = 1
	CERTACT_REVOKE CertAction = 2
)

type SignAction int

const (
	SIGNACT_SIGN   SignAction = 1
	SIGNACT_REVOKE SignAction = 2
	SIGNACT_ACCEPT SignAction = 3
)

type CertPrint int

const (
	CERTPRNT_DETAIL CertPrint = 1
	CERTPRNT_CERT   CertPrint = 2
)*/

func main() {

	cmdIsEthPrint := flag.Bool("ethprint", false,
		"Printing identity from blockchain corresponfing to email or fingerprint parameter\n"+
			"Example1: ethpgp -email=mymail@uni.lu -ethprint\n"+
			"Example2: ethpgp -finger=20HEXDIGITFINGERPRINT -ethprint (with -finger=A123BC..)\n")
	cmdIsGetCert := flag.Bool("getcert", false,
		"Stdout of an armored pgp key from blockchain corresponfing to email or fingerprint parameter\n"+
			"Example: ethpgp -email=mymail@uni.lu -getcert\n")
	cmdIsLoad := flag.Bool("load", false,
		"To load a pgp key into blockchain corresponding to email or fingerprint.\n"+
			"Password of Ethereum user (written in pgp key Comment field) is required\n"+
			"Example1: ethpgp -email=mymail@uni.lu -load\n"+
			"Example2: ethpgp -finger=20HEXDIGITFINGERPRINT -load (with -finger=A123BC..)\n")
	cmdIsRevoke := flag.Bool("revoke", false,
		"Revocation of your pgp key in the blockchain\n"+
			"Password of Ethereum user (written in pgp key Comment field) is required\n"+
			"Example: ethpgp -email=mymail@uni.lu -revoke\n")
	cmdSign := flag.String("sign", "",
		"Load of a pgp key signature to the blockchain. Specify finger or main email of pgp key to sign\n"+
			"Password of Ethereum user (written in pgp key Comment field) is required\n"+
			"IMPORTANT: the pgp key should be already signed with GPG app.\n"+
			"	   The forced pgp signing was (temporarily?) removed due to security reasons\n"+
			"Example: ethpgp -email=mymail@uni.lu -sign=test1@test.lu\n")
	cmdRevokeSign := flag.String("revokesign", "",
		"Revocation of pgp key signature in the blockchain.\n"+
			"Specify finger or main email of the pgp key to sign\n"+
			"Password of Ethereum user (written in pgp key Comment field) is required\n"+
			"Example1: ethpgp -email=mymail@uni.lu -revokesign=test1@test.lu\n")
	cmdAcceptSignedCert := flag.String("accept", "",
		"Acceptation of pgp key signed by third party and loaded into the blockchain."+
			"Specify email or fingerprint of the third party signing the your pgp key."+
			"Password of Ethereum user (written in pgp key Comment field) is required"+
			"Example: ethpgp -email=mymail@test.lu -accept=myfriend@uni.lu")

	prmEmail := flag.String("email", "", "main(!) email, corresponding to the key to process according to command\n")
	prmFinger := flag.String("finger", "", "fingerprint of the key to process according to command\n")

	flag.Parse()

	err := pghkp.LoadConfig()
	if err != nil {
		fmt.Printf("ERROR IN CERT LOAD: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting processing...")

	if (*cmdIsLoad == false) && (*cmdIsRevoke == false) && (*cmdIsEthPrint == false) &&
		(*cmdSign == "") && (*cmdRevokeSign == "") && (*cmdAcceptSignedCert == "") {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if (*cmdIsLoad == true) && (*cmdIsRevoke == true) {
		fmt.Printf("Not possible to load and revoke simultaneously\n")
		os.Exit(1)
	}
	if (*cmdSign != "") && (*cmdRevokeSign != "") {
		fmt.Printf("Not possible to load and revoke signatures simultaneously\n")
		os.Exit(1)
	}

	if (*prmEmail == "") && (*prmFinger == "") {
		fmt.Printf("Finger or Email of the public key must be specified\n")
		os.Exit(1)
	}
	if *cmdIsLoad == true {
		// certContnent == "" to read from a local pgp key ring
		err := pghkp.ActionCertEth(*prmEmail, *prmFinger, "" /*certContent*/, pghkp.CERTACT_LOAD)
		if err != nil {
			fmt.Printf("ERROR IN CERT LOAD: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdIsRevoke == true {
		// certContnent == "" to read from a local pgp key ring
		err := pghkp.ActionCertEth(*prmEmail, *prmFinger, "" /*certContent*/, pghkp.CERTACT_REVOKE)
		if err != nil {
			fmt.Printf("ERROR IN CERT REVOKE: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdIsEthPrint == true {
		err := pghkp.PrintEth(*prmEmail, *prmFinger, nil, pghkp.CERTPRNT_DETAIL)
		if err != nil {
			fmt.Printf("ERROR IN PRINT ETH: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdIsGetCert == true {
		err := pghkp.PrintEth(*prmEmail, *prmFinger, nil, pghkp.CERTPRNT_CERT)
		if err != nil {
			fmt.Printf("ERROR IN GET CERT: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdSign != "" {
		err := pghkp.ActionSignEth(*prmEmail, *prmFinger, *cmdSign, pghkp.SIGNACT_SIGN)
		if err != nil {
			fmt.Printf("ERROR IN SIGN: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdRevokeSign != "" {
		err := pghkp.ActionSignEth(*prmEmail, *prmFinger, *cmdRevokeSign, pghkp.SIGNACT_REVOKE)
		if err != nil {
			fmt.Printf("ERROR IN REVOKE SIGN: %v\n", err)
			os.Exit(1)
		}
	}
	if *cmdAcceptSignedCert != "" {
		var strIntroduceEmail, strIntroduceFinger, strUserCert string
		if strings.Contains(*cmdAcceptSignedCert, "@") == true {
			strIntroduceEmail = *cmdAcceptSignedCert
		} else {
			strIntroduceFinger = *cmdAcceptSignedCert
		}
		if *prmFinger != "" {
			strUserCert = *prmFinger
		} else {
			strUserCert = *prmEmail
		}
		err := pghkp.ActionSignEth(strIntroduceEmail, strIntroduceFinger, strUserCert, pghkp.SIGNACT_ACCEPT)
		if err != nil {
			fmt.Printf("ERROR IN SIGN: %v\n", err)
			os.Exit(1)
		}
	}

}
