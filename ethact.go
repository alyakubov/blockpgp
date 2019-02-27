package pghkp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var gConfigFile string = "./config/ethpgp.conf"

var gConfig struct {
	ContractHash string `json:"contractHash"`
	IPCpath      string `json:"IPCpath"`
	KeyDir       string `json:"keyDir"`
	ContractAddr common.Address
}

const HELP_USERADDR string = "User's blockchain address (0x..) should be put into the comment field of the certificate after 'blockchain:' statement, for example 'blockchain:0x023df..'"

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
)

/*
	if certContent == "" the certificate is read from local pgp certificate storage (pgp keyring)
*/
func ActionCertEth(strEmail string, strFinger string, certContent string, action CertAction) (err error) {
	userAddrEth, _ /*identity*/, name, email, finger, _ /* keyId */, err := getPGPData(strEmail, strFinger, certContent)
	if err != nil {
		return err
	}
	pswd, err := AskPassword(userAddrEth)
	if err != nil {
		return err
	}

	//fmt.Printf("DEBUG Result -- %v, %v, %v, %v, %v", email, identity, pswd, userAddrEth.String(), finger)
	fmt.Println("In LoadCert: about to connect to Ethereum under %s, name %v, email %v, finger %x",
		userAddrEth.String(), name, email, finger)

	pPgpOrch, err := InitEthOrchestr()
	if err != nil {
		fmt.Printf("Failed to retrieve Orchestr: %v", err)
		return err
	}
	evInd, err := pPgpOrch.GetEvIndCertId(&bind.CallOpts{}, []byte(finger[:]))
	if err != nil {
		return errors.New(fmt.Sprintf("GetEvIndCertId: %v", err))
	}
	bufferCertContent, err := ExportLocalGpgCert(finger)
	if err != nil {
		return err
	}

	var ethSess interface{}
	switch action {
	case CERTACT_LOAD:
		pPgpIden, err := InitEthIden()
		if err != nil {
			fmt.Printf("Failed to retrieve Iden contr: %v", err)
			return err
		}
		ethSess, err = GetEthSession(*pPgpIden, userAddrEth, pswd)
		if err != nil {
			fmt.Printf("Failed to connect to the Ethereum client: %v", err)
			return err
		}
	case CERTACT_REVOKE:
		/*Already done above:  pgpOrch, err := InitEthOrchestr()*/
		ethSess, err = GetEthSession(*pPgpOrch, userAddrEth, pswd)
		if err != nil {
			fmt.Printf("Failed to connect to the Ethereum client: %v", err)
			return err
		}
	default:
		return errors.New(fmt.Sprintf("Unknown CERTACT parameter"))
	}

	var evNameHash string
	evEmitContrAddr := gConfig.ContractAddr
	switch typ := ethSess.(type) {
	case PgpIdenSession:
		ethIdenSession := PgpIdenSession(typ)
		_, err = ethIdenSession.NewCertificate(email, []byte(finger[:]), bufferCertContent.Bytes(), name, userAddrEth)
		if err != nil {
			return errors.New(fmt.Sprintf("Certificate Load / Revoke: %v", err))
		}
		/* WE DO EXCLUDE THE LEADING 0x...
		web3.sha3("evNewCertificateReturn(uint256,int256,string,uint256)")
			"0x23eb6b1bea389065ac60a5eabcdf5de5bf39835c4f98b15144a0fb37ae4d68c5"
			evNameHash = "23eb6b1bea389065ac60a5eabcdf5de5bf39835c4f98b15144a0fb37ae4d68c5"
		*/
		evNameHash = "23eb6b1bea389065ac60a5eabcdf5de5bf39835c4f98b15144a0fb37ae4d68c5"
		evEmitContrAddr, err = pPgpOrch.GetIdenAddr(&bind.CallOpts{})
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to get Iden contr addr in Cert Action: %v", err))
		}

	case PgpOrchestrSession:
		ethOrchestrSession := PgpOrchestrSession(typ)
		_, err = ethOrchestrSession.RevokeCertificate([]byte(finger[:]), big.NewInt(0))
		if err != nil {
			return errors.New(fmt.Sprintf("Certificate Load / Revoke: %v", err))
		}
		/* WE DO EXCLUDE THE LEADING 0x...
		web3.sha3("evRevokeCertificateReturn(uint256,int256,string)")
			"0xcec26ed85fd876c424748e5ec33d9d3d79d81433a741608e9c0919aec2e2a0fc"
			evNameHash = "cec26ed85fd876c424748e5ec33d9d3d79d81433a741608e9c0919aec2e2a0fc"
		*/
		evNameHash = "cec26ed85fd876c424748e5ec33d9d3d79d81433a741608e9c0919aec2e2a0fc"
		evEmitContrAddr = gConfig.ContractAddr

	default:
		return errors.New(fmt.Sprintf("Wrong type of scontr session"))
	}

	//_ /*res*/, _ /*msg*/, err = getEventReturn(evNameHash, evEmitContrAddr, evInd)
	res, msg, err := getEventReturn(evNameHash, evEmitContrAddr, evInd)
	if err != nil {
		return errors.New(fmt.Sprintf("getEventReturn: %v", err))
	}
	fmt.Printf("Operation result: %v, %s\n", res, msg)
	return nil
}

func ActionSignEth(strEmail string, strFinger string, strToSign string, action SignAction) (err error) {
	var strToSignEmail, strToSignFinger string
	if strings.Contains(strToSign, "@") == true {
		strToSignEmail = strToSign
	} else {
		strToSignFinger = strToSign
	}
	userAddrEth, identity, _ /*name*/, _ /*email*/, finger, keyId, err := getPGPData(strEmail, strFinger, "")
	if err != nil {
		return err
	}
	signAddrEth, signIdentity, _ /*signName*/, _ /*signEmail*/, signFinger, signKeyId, err := getPGPData(strToSignEmail, strToSignFinger, "")
	if err != nil {
		return err
	}

	pswd, err := AskPassword(userAddrEth)
	if err != nil {
		return err
	}
	//fmt.Printf("DEBUG Main Cert Result -- %v, %v, %v, %v, %x\n", email, identity, pswd, userAddrEth.String(), finger)
	//fmt.Printf("DEBUG Signed Cert Result -- %v, %v, %v, %x\n", signEmail, signIdentity, signAddrEth.String(), signFinger)

	//fmt.Printf("DEBUG Param for GPG export cert %s\n", strings.ToUpper(hex.EncodeToString(signFinger[:])))
	bufferCertContent, err := ExportLocalGpgCert(signFinger)
	if err != nil {
		return err
	}

	isSigned, err := CheckSign(keyId, identity, finger, signKeyId, signIdentity, signFinger)
	if err != nil {
		return err
	}
	if isSigned == false {
		return errors.New(fmt.Sprintf("Certificate %s is not signed by %s", signIdentity, identity))
	}

	pPgpIden, err := InitEthIden()
	if err != nil {
		fmt.Printf("Failed to retrieve Iden contr: %v", err)
		return err
	}
	pPgpOrch, err := InitEthOrchestr()
	if err != nil {
		fmt.Printf("Failed to retrieve Orchestr: %v", err)
		return err
	}

	var ethSess interface{}
	fmt.Println("In SignEth: about to connect to Ethereum....")
	switch action {
	case SIGNACT_ACCEPT:
		//err = ConnectEth(signAddrEth, pswd, &ethSession)
		ethSess, err = GetEthSession(*pPgpIden, signAddrEth, pswd)
	case SIGNACT_SIGN:
		//err = ConnectEth(userAddrEth, pswd, &ethSession)
		ethSess, err = GetEthSession(*pPgpIden, userAddrEth, pswd)
	case SIGNACT_REVOKE:
		//err = ConnectEth(userAddrEth, pswd, &ethSession)
		ethSess, err = GetEthSession(*pPgpOrch, userAddrEth, pswd)
	}
	if err != nil {
		fmt.Printf("Failed to connect to the Ethereum client: %v", err)
		return err
	}

	/*var ethOrchSession PgpOrchestrSession
	switch typ := ethSess.(type) {
	case PgpOrchestrSession:
		ethSession = PgpOrchestrSession(typ)
	case PgpIdenSession:
		ethSession = PgpIdenSession(typ)
	default:
		return errors.New(fmt.Sprintf("Wrong type of scontr session"))
	}*/

	fmt.Println("Connected to Ethereum")
	evInd, err := pPgpOrch.GetEvIndSignId(&bind.CallOpts{}, []byte(finger[:]), []byte(signFinger[:]))
	if err != nil {
		return errors.New(fmt.Sprintf("GetEvIndCertId: %v", err))
	}
	//fmt.Printf("DEBUG Parameters to GetEvIndCertId: finger=%x, signedFinger=%x, exId=%x\n",[]byte(finger[:]), []byte(signFinger[:]), evInd.Bytes())

	/* WE DO EXCLUDE THE LEADING 0x...
	web3.sha3("evNewSigntReturn(uint256,int256,string)")
		"0x651780c7f31af4171f8835ee81e43db1bdccfdb21b4dd98288dccaa59c95dfb4"
		evNameHash = "651780c7f31af4171f8835ee81e43db1bdccfdb21b4dd98288dccaa59c95dfb4"
	web3.sha3("evRevokeSigntReturn(uint256,int256,string)")
		"0xfee83168003f5bfa2fe50e8ea89dfc141f1eaac77f276b77290ef7a02904fef3"
		evNameHash = "fee83168003f5bfa2fe50e8ea89dfc141f1eaac77f276b77290ef7a02904fef3"
	web3.sha3("evAcceptedCertSignature(uint256,int256,string,uint256)")
		"0xf50278e117d4f07fd58db02fc969c9b1a201c083f5d96ce0b1a7a197712d4647"
		evNameHash = "f50278e117d4f07fd58db02fc969c9b1a201c083f5d96ce0b1a7a197712d4647"
	*/
	var evNameHash string
	var evEmitContrAddr common.Address
	switch action {
	case SIGNACT_SIGN:
		var ethIdenSession PgpIdenSession
		switch typ := ethSess.(type) {
		case PgpIdenSession:
			ethIdenSession = PgpIdenSession(typ)
		default:
			return errors.New(fmt.Sprintf("Wrong type of scontr session"))
		}
		_, err = ethIdenSession.NewSignt([]byte(finger[:]), []byte(signFinger[:]), bufferCertContent.Bytes())
		evNameHash = "651780c7f31af4171f8835ee81e43db1bdccfdb21b4dd98288dccaa59c95dfb4"
		evEmitContrAddr, err = pPgpOrch.GetIdenAddr(&bind.CallOpts{})
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to get Iden contr addr in Signt Action: %v", err))
		}
	case SIGNACT_REVOKE:
		var ethOrchSession PgpOrchestrSession
		switch typ := ethSess.(type) {
		case PgpOrchestrSession:
			ethOrchSession = PgpOrchestrSession(typ)
		default:
			return errors.New(fmt.Sprintf("Wrong type of scontr session"))
		}
		_, err = ethOrchSession.RevokeSignt([]byte(finger[:]), []byte(signFinger[:]), big.NewInt(0))
		evNameHash = "fee83168003f5bfa2fe50e8ea89dfc141f1eaac77f276b77290ef7a02904fef3"
		evEmitContrAddr = gConfig.ContractAddr
	case SIGNACT_ACCEPT:
		var ethIdenSession PgpIdenSession
		switch typ := ethSess.(type) {
		case PgpIdenSession:
			ethIdenSession = PgpIdenSession(typ)
		default:
			return errors.New(fmt.Sprintf("Wrong type of scontr session"))
		}
		_, err = ethIdenSession.AcceptProposedCert([]byte(finger[:]), []byte(signFinger[:]))
		evNameHash = "f50278e117d4f07fd58db02fc969c9b1a201c083f5d96ce0b1a7a197712d4647"
		evEmitContrAddr, err = pPgpOrch.GetIdenAddr(&bind.CallOpts{})
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to get Iden contr addr in Signt Action: %v", err))
		}
	}
	if err != nil {
		return errors.New(fmt.Sprintf("Signing operations with  Certificate: %v", err))
	}
	res, msg, err := getEventReturn(evNameHash, evEmitContrAddr, evInd)
	if err != nil {
		return errors.New(fmt.Sprintf("getEventReturn: %v", err))
	}
	fmt.Printf("Operation result: %v, %s\n", res, msg)
	return nil
}

/*
 pOutCert => pointer to string for action=CERTPRNT_CERT to return certificate's armored content
   if pOutCert == nil then output to stdout
*/
func PrintEth(strEmail string, strFinger string, pOutCert *string, action CertPrint) (err error) {
	_ /*userAddrEth*/, _ /*identity*/, name, email, finger, _ /* keyId */, err := getPGPData(strEmail, strFinger, "")
	if err != nil {
		return err
	}

	pPgpOrchestr, err := InitEthOrchestr()
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to retrieve Orchestr smart contr: %v", err))
	}
	pPgpIden, err := InitEthIden()
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to retrieve Orchestr smart contr: %v", err))
	}

	/* ORCHESTR smart contract now contains shell functions
	pgpContract, err := InitEthIden()
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to connect to the Ethereum client: %v", err))
	}*/

	if action == CERTPRNT_CERT {
		bCert, err := pPgpIden.GetIdenOwnCert(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("GetCert with GetIdenOwnCert: %v", err))
		}
		if pOutCert == nil {
			fmt.Println(string(bCert))
		} else {
			*pOutCert = strings.TrimSpace(string(bCert))
			if len(*pOutCert) == 0 {
				return errors.New(fmt.Sprintf("Certificate has empty content, finger = %s", strFinger))
			}
		}
		return nil
	}

	fmt.Printf("Data in blockchain for email=%s, %s\n", strEmail, strFinger)

	var startI, finishI uint64
	if strFinger == "" {
		fingerNum, err := pPgpOrchestr.GetFingersLen(&bind.CallOpts{}, strEmail)
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth with GetFingerLen: %v", err))
		}
		fmt.Printf("Number of certificates data for primary email %s: %v\n", email, fingerNum)
		finishI = fingerNum.Len.Uint64()
	} else {
		fingerInd, err := pPgpOrchestr.IsFingersFinger(&bind.CallOpts{}, strEmail, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth with isFingerFingers: %v", err))
		}
		startI = fingerInd.Ind.Uint64()
		finishI = startI + 1
	}

	for i := startI; i < finishI; i++ {
		var printFinger []byte = make([]byte, len(finger))
		if strEmail != "" {
			printFingerStruct, err := pPgpOrchestr.GetFingersItem(&bind.CallOpts{}, strEmail, big.NewInt(int64(i)))
			if err != nil {
				return errors.New(fmt.Sprintf("PrintEth with GetCertFinger: %v", err))
			}
			if printFingerStruct.Err.Int64() != 0 {
				return errors.New(fmt.Sprintf("PrintEth with GetCertFinger error code: %v", printFingerStruct.Err.Int64()))
			}
			copy(printFinger, printFingerStruct.Res)
		} else {
			copy(printFinger, finger[:])
		}
		if !bytes.Equal(printFinger, []byte(finger[:])) {
			return errors.New(fmt.Sprintf(
				"Attention! Fingerprint in Ethereum (%x) does not correspond to fingerprint in gpg(%x)",
				printFinger, []byte(finger[:])))
		}
		fmt.Printf("    The finger print: %x\n", printFinger)

		printName, err := pPgpIden.GetIdenName(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth GetIdenName: %s", err))
		}
		fmt.Printf("    Name corresponding to the certificate: %s\n", printName)
		if printName != name {
			return errors.New(fmt.Sprintf("Attention! Name in Ethereum Identity (%s) does not correspond to name in gpg (%s)",
				printName, name))
		}

		certLoadDate, err := pPgpIden.GetIdenLoadDate(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth GetIdenLoadDate: %v", err))
		}
		fmt.Printf("    Identity was loaded on the folllowing date: %s\n", time.Unix(certLoadDate.Int64(), 0))

		printEmail, err := pPgpIden.GetIdenEmail(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth with GetIdenEmail: %v", err))
		}
		if printEmail != email {
			//return errors.New(fmt.Sprintf(
			fmt.Printf(fmt.Sprintf(
				"Attention! Email in Ethereum Identity (%s) does not correspond to email in gpg / cert index (%s)\n",
				printEmail, email))
		}

		printRevoc, err := pPgpOrchestr.GetCertRevocation(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth with GetIdenRevocation: %v", err))
		}
		if printRevoc.IsRevoked == true {
			fmt.Printf("    Identity was revoked on the folllowing date: %s\n", time.Unix(printRevoc.RevDate.Int64(), 0))
		} else {
			if printRevoc.RevDate.Int64() == 0 {
				fmt.Printf("    Identity is active with no expiration date defined\n")
			} else {
				fmt.Printf("    Identity is active with expiration on %s\n", time.Unix(printRevoc.RevDate.Int64(), 0))
			}
		}

		signtLen, err := pPgpIden.GetSigntLen(&bind.CallOpts{}, finger[:])
		if err != nil {
			return errors.New(fmt.Sprintf("PrintEth GetIdenLoadDate: %v", err))
		}
		if signtLen.Err.Int64() == 1 {
			fmt.Printf("    Identity signed no third-party certificates\n")
			return nil
		}
		fmt.Printf("    Identity signed %v third-party certificates:\n", signtLen.Len.Int64())
		for i := int64(0); i < signtLen.Len.Int64(); i++ {
			signt, err := pPgpIden.GetSignedFinger(&bind.CallOpts{}, finger[:], big.NewInt(i))
			if err != nil {
				return errors.New(fmt.Sprintf("PrintEth GetSignedFinger: %v", err))
			}
			if signt.Err.Int64() != 0 {
				fmt.Printf("        Error in retrieving signature: %v\n", signt.Err.Int64())
				continue
			}
			if signt.RevocationDate.Int64() == 0 {
				fmt.Printf("        Signed certificate: %x\n", signt.SignedFinger)
			} else {
				fmt.Printf("        Signature for %x was revoked on %s\n",
					signt.SignedFinger, time.Unix(certLoadDate.Int64(), 0))
			}
		}
	}

	return nil
}

/*
Looking for Announce Events to push events to other
*/
func GetCertAnnounces() (events []PgpIdenEvNewCertificateAnnounce, err error) {
	/*
		// Dial to Ethereum here

		query := ethereum.FilterQuery{
			FromBlock: nil,
			ToBlock:   nil,
			//Topics:    [][]common.Hash{{evCallHash}}, //[][]common.Hash --- ?? we do not specify the specific event
			Addresses: []common.Address{gConfig.ContractAddr}}

		s, err := client.FilterLogs(context.TODO(), query, logs)
		if err != nil {
			return 0, "", errors.New(fmt.Sprintf("Failed to establish Ethereum event filter: %v", err))
		}

		contractAbi, err := abi.JSON(strings.NewReader(string(store.StoreABI)))
		if err != nil {
			log.Fatal(err)
		}
		for _, vLog := range logs {
			event := struct {
				finger []byte
				Value  *big.Int
			}{}
			err := contractAbi.Unpack(&event, "ItemSet", vLog.Data)
			if err != nil {
				log.Fatal(err)
			}
		}
	*/
	//fmt.Println("DEBUG: about to init ethIden contract")
	pgpContract, err := InitEthIden()
	if err != nil {
		return events, errors.New(fmt.Sprintf("Failed to connect to the Ethereum client: %v", err))
	}
	//fmt.Println("DEBUG: ethIden contract is inited")

	var opt bind.FilterOpts
	iter, err := pgpContract.FilterEvNewCertificateAnnounce(&opt)
	if err != nil {
		return events, errors.New(fmt.Sprintf("Failed in retrieving event iterator: %v", err))
	}
	defer iter.Close()
	//fmt.Println("DEBUG: about to loop through events")
	iter.Next()
	if iter.Error() != nil {
		return events, errors.New(fmt.Sprintf("Failed in retrieving first event data: %v", err))
	}
	for iter.done == false {
		events = append(events, *iter.Event)
		iter.Next()
		if iter.Error() != nil {
			return events, errors.New(fmt.Sprintf("Failed in retrieving next event data: %v", err))
		}
	}
	return events, nil
}

/*
	Getting results from main smart contract functions through Events
		evNumHash = string with the hash WITHOUT leading "0x"
		web3.sha3("evNewCertificateReturn(uint256,int256,string,uint256)")
			"0x23eb6b1bea389065ac60a5eabcdf5de5bf39835c4f98b15144a0fb37ae4d68c5"
			evNameHash = "23eb6b1bea389065ac60a5eabcdf5de5bf39835c4f98b15144a0fb37ae4d68c5"
*/
func getEventReturn(evNameHash string, contrAddr common.Address, evInd *big.Int) (result int64, msg string, err error) {
	//https://ethereum.stackexchange.com/questions/28637/how-to-decode-log-data-in-go/32021
	//https://goethereumbook.org/event-read/
	var evCallHash, evIndHash common.Hash
	bytesCallHash, err := hex.DecodeString(evNameHash)
	if err != nil {
		return 0, "", errors.New(fmt.Sprintf("Failed to create CallHash for the event: %v", err))
	}
	evCallHash.SetBytes(bytesCallHash)
	fmt.Printf("DEBUG: callHash: %s\n", evCallHash.Hex())
	bytesEvInd := evInd.Bytes()
	if len(bytesEvInd) != 32 {
		return 0, "", errors.New(fmt.Sprintf("Length is not 20 for %x", evInd.Bytes()))
	}
	evIndHash.SetBytes(bytesEvInd)
	fmt.Printf("DEBUG: bytesEvInd: %s\n", evIndHash.Hex())

	query := ethereum.FilterQuery{
		FromBlock: nil,
		ToBlock:   nil,
		Topics:    [][]common.Hash{{evCallHash}, {evIndHash}}, //[][]common.Hash
		Addresses: []common.Address{contrAddr}}
	var logs = make(chan types.Log) //, 2)

	client, err := ethclient.Dial(gConfig.IPCpath)
	if err != nil {
		return 0, "", errors.New(fmt.Sprintf("Failed to connect to the Ethereum client: %v", err))
	}
	s, err := client.SubscribeFilterLogs(context.TODO(), query, logs)
	if err != nil {
		return 0, "", errors.New(fmt.Sprintf("Failed to establish Ethereum event filter: %v", err))
	}

	errChan := s.Err()
	for {
		select {
		case err := <-errChan:
			return 0, "", errors.New(fmt.Sprintf("Event Logs subscription error: %v", err))
		case l := <-logs:
			//fmt.Printf("DEBUG Event Data: %x\n", l.Data)
			return ProcEventInteger(l.Data)
		}
	}
}

func ProcEventInteger(evData []byte) (result int64, msg string, err error) {

	/*if len(evData) != 32*2 {
		return 0, errors.New(fmt.Sprintf("Length of the data string is not valid: %v, dataString: %x, dataHash: %x",
			len(evData), evData, dataHash))
	}*/

	if len(evData) < 64 {
		return 0, "", errors.New("Event data (%v bytes) should be at least 64 bytes")
	}

	bRes := evData[:32]
	longRes := big.NewInt(0)
	longRes.SetBytes(bRes)
	result = longRes.Int64()

	bMsg := evData[32:]
	bMsgLen := bMsg[:32]
	longMsgLen := big.NewInt(0)
	longMsgLen.SetBytes(bMsgLen)
	if len(bMsg) > 32 {
		bMsgStr := bMsg[32:]
		msg = string(bMsgStr)
	} else {
		msg = ""
	}
	return result, msg, nil
}

func ExportLocalGpgCert(finger [20]byte) (bufferCertContent bytes.Buffer, err error) {
	cmd := exec.Command("gpg", "-a", "--export", strings.ToUpper(hex.EncodeToString(finger[:])))
	var bufferErr bytes.Buffer
	cmd.Stdout = &bufferCertContent
	cmd.Stderr = &bufferErr
	if err = cmd.Run(); err != nil {
		return bufferCertContent, errors.New(fmt.Sprintf("GPG call's error: %v", err))
	}
	if len(bufferErr.Bytes()) > 0 {
		return bufferCertContent, errors.New(fmt.Sprintf("GPG returns error: %v", bufferErr.String()))
	}
	return bufferCertContent, nil
}

func GetGpgEntity(pubring openpgp.EntityList, keyId uint64, finger [20]byte) (entity *openpgp.Entity, err error) {
	keys := pubring.KeysByIdUsage(keyId, packet.KeyFlagSign|packet.KeyFlagCertify)
	if len(keys) == 0 {
		return nil, errors.New(fmt.Sprintf("KeyId %s is not found in the key ring", keyId))
	}
	var isKeyFound bool = false
	for _, key := range keys {
		if bytes.Compare(key.Entity.PrimaryKey.Fingerprint[:], finger[:]) == 0 {
			isKeyFound = true
			entity = key.Entity
			break
		}
	}
	if isKeyFound == false {
		return nil, errors.New(fmt.Sprintf("KeyId %s (%n instances) does not have finger %x", keyId, len(keys), finger))
	}
	return entity, nil
}

/*
 */
func CheckSign(keyId uint64, identity string, finger [20]byte,
	signKeyId uint64, signIdentity string, signFinger [20]byte) (isSigned bool, err error) {
	//https://github.com/golang/crypto/blob/master/openpgp/keys_test.go
	//line 363
	pubring, err := OpenKeyRing("")
	if err != nil {
		return false, errors.New(fmt.Sprintf("Read from gpg keyring: %v", err))
	}
	entity, err := GetGpgEntity(pubring, keyId, finger)
	if err != nil {
		return false, err
	}

	signEntity, err := GetGpgEntity(pubring, signKeyId, signFinger)
	if err != nil {
		return false, err
	}
	signIdent := signEntity.Identities[signIdentity]
	if signIdent == nil {
		return false, errors.New(fmt.Sprintf("KeyId %s and identity %s not found", signKeyId, signIdentity))
	}

	for _, sig := range signIdent.Signatures {
		if sig.IssuerKeyId == nil || *sig.IssuerKeyId != entity.PrimaryKey.KeyId {
			continue
		}

		err := entity.PrimaryKey.VerifyUserIdSignature(signIdentity,
			signEntity.PrimaryKey, sig)
		if err != nil {
			return false, errors.New(fmt.Sprintf("Error verifying signature of %s: %s", identity, err))
		} else {
			return true, nil
		}
	}
	return false, nil
}

func getPGPData(strEmail string, strFinger string, certContent string) (userAddrEth common.Address,
	identity string, name string, email string, finger [20]byte, keyId uint64, err error) {

	pubring, err := OpenKeyRing(certContent)
	if err != nil {
		return common.Address{}, "", "", "", finger, 0,
			errors.New(fmt.Sprintf("Read from gpg keyring: %v", err))
	}

	strEmail = strings.ToLower(strings.Trim(strEmail, " "))
	strFinger = strings.ToLower(strings.Trim(strFinger, " "))
	if strEmail == "" && strFinger == "" {
		return common.Address{}, "", "", "", finger, 0,
			errors.New(fmt.Sprintf("Both email and fingerprint params are empty"))
	}
	baFinger, err := hex.DecodeString(strFinger)
	if err != nil {
		return common.Address{}, "", "", "", finger, 0,
			errors.New(fmt.Sprintf("Decode of Finger (%v) returns an error: %v", strFinger, err))
	}

	for _, entity := range pubring {
		//fmt.Printf("Ent %x\n", entity.PrimaryKey.Fingerprint)
		if strFinger != "" {
			if bytes.Compare(baFinger, entity.PrimaryKey.Fingerprint[:]) != 0 {
				continue
			}
		}
		for _, ident := range entity.Identities {
			//fmt.Printf("   Ident %s, %s, %s\n", ident.UserId.Email, ident.UserId.Name, ident.UserId.Comment)
			if strEmail != "" {
				if strings.ToLower(strings.Trim(ident.UserId.Email, " ")) != strEmail {
					continue
				}
			}
			isAddrFound, ethAddr, err := parseCommentEthAdrress(ident.UserId.Comment)
			if err != nil {
				fmt.Printf("\nIMPORTANT: Icorrect blockchain block -- %s\n", err)
				continue
			}
			if !isAddrFound {
				fmt.Printf("\nIMPORTANT: problems in %s with comment %s - no blockchain spec\n",
					ident.UserId.Name, ident.UserId.Comment)
				continue
			}
			return ethAddr, ident.UserId.Id, ident.UserId.Name, ident.UserId.Email, entity.PrimaryKey.Fingerprint,
				entity.PrimaryKey.KeyId, nil
		}
	}
	return common.Address{}, "", "", "", finger, 0, errors.New(fmt.Sprintf("Read from keyring: required key not found"))
}

/*
Searches for blockchain:0x000... in the string (comment of pgp certificate)
!! isFound should be checked with error as well!!!
   for instance, address can be incorrect
*/
func parseCommentEthAdrress(strComment string) (isFound bool, ethAddr common.Address, err error) {
	const BLOCKCH = "blockchain:"
	fields := strings.Fields(strComment)
	for _, field := range fields {
		posEthAddr := strings.Index(strings.ToLower(field), BLOCKCH)
		if posEthAddr < 0 {
			continue
		}
		strEthAddr := field[posEthAddr+len(BLOCKCH):]
		if common.IsHexAddress(strEthAddr) {
			ethAddr = common.HexToAddress(strEthAddr)
		} else {
			return true, common.Address{}, errors.New(
				fmt.Sprintf("In comment %s address %s is not correct", strComment, strEthAddr))
		}
		if isFound {
			return true, common.Address{}, errors.New(
				fmt.Sprint("In comment %s another blockchain spec found: %s", strComment, field))
		}
		isFound = true
	}
	return isFound, ethAddr, nil
}

/*
SPECIFICALLY FOR STORAGE
if just in one keyword blockchain spec found then OK
if in more than one keywords blockchain spec found then ERROR
*/
func getEthAddrKeywords(arrKeywords []string) (isFound bool, ethAddr common.Address, err error) {
	for _, keywords := range arrKeywords {
		var strComment string
		lbr, rbr := strings.Index(keywords, "("), strings.LastIndex(keywords, ")")
		if lbr != -1 && rbr > lbr {
			strComment = keywords[lbr+1 : rbr]
		} else {
			continue
		}
		isF, eAd, e := parseCommentEthAdrress(strComment)
		//fmt.Printf("getEthAddr %s in %s, isF=%v, address=%v, err=%v\n", strComment, keywords, isF, eAd.String(), e)
		if e != nil {
			err = e
			continue
		}
		if isF == false {
			continue
		}
		if isFound == true {
			return true, common.Address{}, errors.New(
				fmt.Sprint("Another correct blockch spec found (%s) in addition to addr %x", keywords, ethAddr))
		}
		isFound = true
		ethAddr = eAd
		err = nil
	}
	return isFound, ethAddr, err
}

/*
if certContent is empty, local keyring os used
*/
func OpenKeyRing(certContent string) (pubring openpgp.EntityList, err error) {
	if certContent != "" {
		return openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(certContent)))
	}

	cmd := exec.Command("gpg", "-a", "--export")
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	if err != nil {
		return pubring, err
	}
	if errb.Len() > 0 {
		return pubring, errors.New(fmt.Sprintf("gpg's errout: %s", errb.String()))
	}
	pubring, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(outb.Bytes()))
	if err != nil {
		return pubring, errors.New(fmt.Sprintf("Read from gpg keyring: %v", err))
	}
	return pubring, nil
}

func AskPassword(userAddrEth common.Address) (pswd string, err error) {

	return "ira", nil
	/* TEMPORARY REMOVED!!!

	//https://stackoverflow.com/questions/2137357/getpasswd-functionality-in-go
	fmt.Printf("Please type in the password for Ehereum account %s:", userAddrEth.String())
	// Common settings and variables for both stty calls.
	attrs := syscall.ProcAttr{
		Dir:   "",
		Env:   []string{},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys:   nil}
	var ws syscall.WaitStatus

	// Disable echoing.
	pid, err := syscall.ForkExec(
		"/bin/stty",
		[]string{"stty", "-echo"},
		&attrs)
	if err != nil {
		return "", err
	}

	// Wait for the stty process to complete.
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return "", err
	}

	// Echo is disabled, now grab the data.
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	// Re-enable echo.
	pid, err = syscall.ForkExec(
		"/bin/stty",
		[]string{"stty", "echo"},
		&attrs)
	if err != nil {
		panic(err)
	}

	// Wait for the stty process to complete.
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		panic(err)
	}

	return strings.TrimSpace(text), nil
	*/
}

/*
   pgpContract == PgpIden or PgpOrchestr
   ptrPGPSession == PgpIdenSession or PgpOrchestrSession
*/
func GetEthSession(pgpContract interface{}, userAddr common.Address, pswd string) (pgpSession interface{}, err error) {
	fmt.Printf("Connecting to Ethereum path: %s\n", gConfig.IPCpath)

	// Instantiate the contract, the address is taken from eth at the moment of contract initiation
	/*pgpContract, err := InitEthIden()
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to instantiate a smart contract: %v", err))
	}*/

	fmt.Printf("Logging into Ethereum as a user %v\n", userAddr.String())
	if (userAddr == common.Address{}) {
		return nil, errors.New("User address is zero")
	}
	keyFile, err := FindKeyFileEth(userAddr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to find key file for account %v. %v ", userAddr.String(), err))
	}
	fmt.Printf("Key file is found: %s\n", keyFile)

	key, err := ioutil.ReadFile(gConfig.KeyDir + keyFile)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Key File error %v for %v", err, gConfig.KeyDir+keyFile))
	}

	auth, err := bind.NewTransactor(strings.NewReader(string(key)), pswd)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create authorized transactor: %v", err))
	}

	callOpts := bind.CallOpts{
		Pending: true,
	}
	transactOpts := bind.TransactOpts{
		From:   auth.From,
		Signer: auth.Signer,
		//GasLimit: big.NewInt(2000000),
		GasLimit: uint64(5000000),
	}

	switch pgpContr := pgpContract.(type) {
	case PgpIden:
		return PgpIdenSession{
			Contract:     &pgpContr,
			CallOpts:     callOpts,
			TransactOpts: transactOpts,
		}, nil
	case PgpOrchestr:
		return PgpOrchestrSession{
			Contract:     &pgpContr,
			CallOpts:     callOpts,
			TransactOpts: transactOpts,
		}, nil
		//default:
		//	fmt.Printf("DEBUG -- Type: %v \n", pgpContract.(type))
	}
	return nil, errors.New(fmt.Sprintf("Unknown type of the PGP contract"))
}

func InitEthOrchestr() (pgpContract *PgpOrchestr, err error) {
	client, err := ethclient.Dial(gConfig.IPCpath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to connect to the Ethereum client: %v", err))
	}

	// Instantiate the contract, the address is taken from eth at the moment of contract initiation
	pgpContract, err = NewPgpOrchestr(gConfig.ContractAddr, client)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to instantiate a smart contract: %v", err))
	}
	return pgpContract, nil
}

func InitEthIden() (pgpContract *PgpIden, err error) {
	client, err := ethclient.Dial(gConfig.IPCpath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to connect to the Ethereum client: %v", err))
	}

	// Instantiate the contract, the address is taken from eth at the moment of contract initiation
	pgpOrchestr, err := NewPgpOrchestr(gConfig.ContractAddr, client)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to instantiate a smart contract: %v", err))
	}
	contrIdenAddr, err := pgpOrchestr.GetIdenAddr(&bind.CallOpts{})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to get Iden contr addr in InitEthEden: %v", err))
	}

	// Instantiate the contract, the address is taken from eth at the moment of contract initiation
	pgpContract, err = NewPgpIden(contrIdenAddr, client)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to instantiate a smart contract: %v", err))
	}
	return pgpContract, nil
}

func FindKeyFileEth(addr common.Address) (keyFileNameEth string, err error) {
	files, err := ioutil.ReadDir(gConfig.KeyDir)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.Name()), strings.ToLower(addr.String()[2:])) == true {
			return f.Name(), nil
		}
	}
	return "", errors.New("Ethereum Key File not found for this address")
}

func LoadConfig() error {
	file, err := os.Open(gConfigFile)
	if err != nil {
		return errors.New(fmt.Sprintf("File error: %v\n", err))
	}
	fmt.Printf("Found configuration file: %s\n", gConfigFile)

	jsonParser := json.NewDecoder(file)
	if err = jsonParser.Decode(&gConfig); err != nil {
		return errors.New(fmt.Sprintf("Parsing config file: %s\n", err.Error()))
	}

	/*b, err := json.Marshal(gConfig)
	if err != nil {
		return errors.New(fmt.Sprintf("Cannot convert conf file into string: %s", err))
	}
	fmt.Printf("DEBUG: Loaded configuration file: %s\n", string(b))*/
	file.Close()

	if common.IsHexAddress(gConfig.ContractHash) == false {
		return errors.New("Config: contract hash is not correct")
	} else {
		gConfig.ContractAddr = common.HexToAddress(gConfig.ContractHash)
	}

	return nil
}
