# BlockPGP

Pretty Good Privacy (PGP) is one of the most prominent cryptographic standards offering end-to-end encryption for email messages and other sensitive information. PGP allows to verify the identity of the correspondent in information exchange as well as the information integrity. PGP implements asymmetric encryption with certificates shared through a network of PGP key servers. Many recent breaches show that certificate infrastructure can be compromised as well as exposed to operational errors. 

We propose a new PGP management framework with the key server infrastructure implemented using blockchain technology. Our framework resolves some problems of PGP key servers focusing in particular on fast propagation of certificate revocation among key servers and elimination of man-in-the-middle risk. We also provided user access right control where only the certificate holder can change information related to the certificate. We designed and developed a prototype for key server deployment on permissioned Ethereum blockchain. Permissioned blockchain should allow to control the costs of PGP key server infrastructure maintenance on the present level.

------------------------------------------
## BlockPGP: Proof-of-Concept of blockchain PGP implementation (Ethereum).

Blockchain-based PGP key server Proof-of-Concept includes two main parts: Unix application providing simple user interface to the key server and Ethereum smart contract providing key server core functionality.

------------------------------------------
## Unix application (ethpgp): 

Command line application was developed with Golang IPC interface to Ethereum geth client assuming no Man-in-the-Middle risks which can be associated with RPC or REST interactions with Ethereum. Application extracts user data from local PGP certificates (or PGP keys) using GNU gpg client, parses certificate’s blockchain user account from Comment field and connects to Ethereum under this user account. Importantly, Ethereum private key corresponding to this user account should be locally stored in corresponding Ethereum folder of key server blockchain instance. Before each Ethereum connection user is asked to enter a password for Ethereum user.


### Command line:

####  -email string

        main(!) email, corresponding to the key to process according to command

####  -finger string

        fingerprint of the key to process according to command

### Command line commands:

####  -ethprint

        Printing identity from blockchain corresponfing to email or fingerprint parameter 
```
        Example1: ethpgp -email=mymail@uni.lu -ethprint
        Example2: ethpgp -finger=20HEXDIGITFINGERPRINT -ethprint (with -finger=A123BC..)
```

####  -getcert

        Stdout of an armored pgp key from blockchain corresponfing to email or fingerprint parameter
```
        Example: ethpgp -email=mymail@uni.lu -getcert
```

####  -load
        To load a pgp key into blockchain corresponding to email or fingerprint.
        Password of Ethereum user (written in pgp key Comment field) is required
```
        Example1: ethpgp -email=mymail@uni.lu -load
        Example2: ethpgp -finger=20HEXDIGITFINGERPRINT -load (with -finger=A123BC..)
```

####  -revoke
        Revocation of your pgp key in the blockchain
        Password of Ethereum user (written in pgp key Comment field) is required
```
        Example: ethpgp -email=mymail@uni.lu -revoke
```

####  -sign string
        Load of a pgp key signature to the blockchain. Specify finger or main email of pgp key to sign
        Password of Ethereum user (written in pgp key Comment field) is required
        IMPORTANT: the pgp key should be already signed with GPG app. 
               The forced pgp signing was (temporarily?) removed due to security reasons
```
        Example: ethpgp -email=mymail@uni.lu -sign=test1@test.lu
```
####  -revokesign string
        Revocation of pgp key signature in the blockchain. 
        Specify finger or main email of the pgp key to sign
        Password of Ethereum user (written in pgp key Comment field) is required
```
        Example1: ethpgp -email=mymail@uni.lu -revokesign=test1@test.lu
```
####  -accept string
        Acceptation of pgp key signed by third party and loaded into the blockchain. 
        Specify email or fingerprint of the third party signing the your pgp key.
        Password of Ethereum user (written in pgp key Comment field) is required
```
        Example: ethpgp -email=mymail@test.lu -accept=myfriend@uni.lu
```

------------------------------------------
### Smart contract (pgp_scont.sol): 

The smart contract provides the following core functions:

• checkRights: validates the rights of the user address in the second parameter to change the blockchain data of PGP certificate identified by its fingerprint. Usually user address parameter is the current Ethereum user specified
by built-in variable msg.sender

• newCertificate: uploads PGP certificate to blockchain alongside with all user data including her/his blockchain address. Rights of the user to upload the certificate are verified with checkRights. Event evNewCertificateReturn is emitted for performance control and error checks.

• newSignt: signs (introduces) certificate of another user and uploads the signed certificate to specifically designed storage of proposed certificates, not accessible by other participants. Only the holder of the signed certificate can download the certificate with getProposedCert function and/or publish it with acceptProposedCert function. Along with event evNewSigntReturn used for error control the event evProposeCertSignature is emitted to acknowledge the certificate holder regarding the signature.

• revokeCert: revokes PGP certificate with the user right validation using checkRights function. Notably, the user
can perform the revocation only with the access to corresponding Ethereum account without use of revocation
certificate. In our view this may be very convenient as it provides another protected way to revoke compromised
certificates. Performance control and error checks are conducted with event evRevokeCertificateReturn

• revokeSignt: revokes user’s signatures (introductions) to PGP certificates of other participants. In OpenPGP concept it is impossible to revoke signatures, but we decided to include it into PoC as an experiment. The user right validation is performed with checkRights function. Event evRevokeSigntReturn is emitted for performance control
and error check.

• acceptPoposedCert: as discussed above on certificate holder request copies signed certificate from introducer’s proposed certificate storage to certificate holder’s ownCert field. Certificate holder is authenticated with checkRights function. Event evAcceptedCertSignature is used for performance control and error check.


---------------------------------------------------------------
### Installation:

1. Create a local directory on you computer and download prepare.bash, deploy_eth.sh and build.bash 

2. Run prepare.bash to download all the source files.

3. To deploy smart contracts to Ethereum (public or private), update deploy_eth.sh with your path to Ethereum blockchain folder and run it. 

4. Build modified hockeypuck and ethpgp with build.bash, executables will be placed into ./bin folder

5. Update config file ./config/ethpgp.conf with the smart contract address ("contractHash" field) and move ./config folder to ./bin

6. To launch the modified hockeypuck:
```
        cd ./bin
        ./hockeypuck -config config/hockeypuck.conf
```

