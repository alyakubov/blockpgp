pragma solidity ^0.4.22;
import "./corchestr.sol";
import "./ciden.sol";


library LIB_revoc {

    struct pgpRevocation {
        address certUser;
        uint revocationDate;
        uint loadDate;
    }
    struct DaRevoc {
        // Here uint is keccak256(finger)  
        mapping(uint => pgpRevocation) certRevocations; /// !!!!
        // Here uint is uint(cat(finger,ind))  NOW ind starts with 0 !!! // OLD -- NOTE!! - ind start with 1, not 0 !!!
        mapping(uint => pgpRevocation) signtRevocations;  /// !!!!
        address cOrchestrAddr;
        LU_PGP_orchestr cOrchestr;
        address cOridenAddr;
        LU_PGP_iden cOriden;
    }
    function getOrchestrAddr(DaRevoc storage self) external view returns(address) {
        return self.cOrchestrAddr;
    }
    function getiOridenAddr(DaRevoc storage self) external view returns(address) {
        return self.cOridenAddr;
    }

    //LU_PGP_fingers internal cFingers;
    //LU_PGP_iden internal cIden;
    function Init(DaRevoc storage self, address _cOrchestrAddr, address _cOridenAddr) external //onlyOwner //setOrchestrAddr(_cOrchestrAddr)
    {
        self.cOrchestrAddr = _cOrchestrAddr; //-- already in modifier
        self.cOrchestr = LU_PGP_orchestr(_cOrchestrAddr);
        //cFingers = LU_PGP_fingers(cOrchestr.getFingersAddr());
        //cIden = LU_PGP_iden(cOrchestr.getIdenAddr());

        self.cOridenAddr = _cOridenAddr; //-- already in modifier
        self.cOriden = LU_PGP_iden(_cOridenAddr);
    }
    modifier checkRef(DaRevoc storage self) {
        require(self.cOrchestrAddr != 0);
        require(self.cOridenAddr != 0);
        //require(cFingers.getOrchestrAddr() == cOrchestrAddr);
        //require(cIden.getOrchestrAddr() == cOrchestrAddr);
        _;
    }

    function getCertRevocation(DaRevoc storage self, bytes _finger) 
                public view checkRef(self) returns(bool isRevoked, uint revDate) 
    { 
        if (self.certRevocations[uint(keccak256(_finger))].loadDate == 0) {
            return (false, 0);
        }
        if (self.certRevocations[uint(keccak256(_finger))].revocationDate > now) {
            return (false, self.certRevocations[uint(keccak256(_finger))].revocationDate);
        } else {
            return (true, self.certRevocations[uint(keccak256(_finger))].revocationDate);
        }
    }

    function getSigntRevocation(DaRevoc storage self, bytes _finger, uint _ind) 
                public view checkRef(self) returns(bool isRevoked, uint revDate) 
    { 
        // cRevoc.signtRevocations[ cOrchestr.getSignRevokeInd( _finger , _ind ) ].revocationDate
        if (self.signtRevocations[ self.cOrchestr.getSignRevokeInd( _finger , _ind ) ].loadDate == 0) {
            return (false, 0);
        }
        if (self.signtRevocations[ self.cOrchestr.getSignRevokeInd( _finger , _ind ) ].revocationDate > now) {
            return (false, self.signtRevocations[ self.cOrchestr.getSignRevokeInd( _finger , _ind ) ].revocationDate);
        } else {
            return (true, self.signtRevocations[ self.cOrchestr.getSignRevokeInd( _finger , _ind ) ].revocationDate);
        }
    }

    /*
        finger = introducing finger
        signed finger = finger which was signed
        returns are based on event:
           0  - success
           1  - no Identy found
           2  - no Signature found
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _trustFinger has incorrect length (not equals 20)
           10-19 - checkRights errors
    */
    function revokeSignt( DaRevoc storage self, bytes _finger, bytes _signedFinger, uint _revocationDate)
                 public checkRef(self)
    {
        int _err;
        uint _ind;
        string memory _errMsg;
        bytes memory _proposedCert;
        bool isFound;

        (_ind, _proposedCert, _err, _errMsg) = self.cOrchestr.findSigntIndex(_finger, _signedFinger);
        if( _err>0 ) {
            emit evRevokeSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), _err, _errMsg);
            return;
        }
        if (_err == 0) {
            isFound = true; 
        }

        //string memory _email = identities[ uint( keccak256( _finger ) ) ].email;

        (_err, _errMsg) = self.cOrchestr.checkRights(_finger, msg.sender);
        if (_err != 0) {
            emit evRevokeSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 10+_err, _errMsg);
            return;
        }
        if(isFound != true) {
            emit evRevokeSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 2,
                 "No corresponding Signature is found");
            return;
        }
        self.signtRevocations[ self.cOrchestr.getSignRevokeInd(_finger, _ind ) ].certUser = msg.sender;
        if (_revocationDate == 0) {
            self.signtRevocations[ self.cOrchestr.getSignRevokeInd(_finger, _ind ) ].revocationDate = now;
        } else {
            self.signtRevocations[ self.cOrchestr.getSignRevokeInd(_finger, _ind ) ].revocationDate = _revocationDate;
        }
        self.signtRevocations[ self.cOrchestr.getSignRevokeInd(_finger, _ind ) ].loadDate = now;
        emit evRevokeSigntReturn( self.cOrchestr.getEvIndSignId( _finger, _signedFinger ), 0, "");
    }

    /*
        returns are based on event:
           0  - success
           1  - no Identy found
           2  - no finger in the fingerList for this return
           6  - Param _finger has incorrect length (not equals 20)
           10-19 - checkRights errors
    */
    function revokeCertificate(DaRevoc storage self, bytes _finger, uint _revocationDate) public checkRef(self) {

        int _err;
        uint _flInd;
        string memory _email;
        string memory _errMsg;

        if (_finger.length != 20) {
            emit evRevokeCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 6,
                 "Param _finger has incorrect length (not equals 20)");
            return;
        }
        // identities[uint( keccak256( _finger) )].loadDate
        if ( self.cOriden.getIdenLoadDate(_finger) == 0) {
            emit evRevokeCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 1, "No Identy found");
            return;
        }

        // identities[ uint( keccak256( _finger ) ) ].email
        _email = self.cOriden.getIdenEmail(_finger);

        (_flInd, _err) = self.cOrchestr.isFingersFinger(_email, _finger);
        if (_err != 0) {
            emit evRevokeCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 2,
                 "No finger in fingerList for this email");
            return;
        }

        (_err, _errMsg) = self.cOrchestr.checkRights(_finger, msg.sender);
        if (_err != 0) {
            emit evRevokeCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 10+_err, _errMsg);
            return;
        }
        self.certRevocations[ uint( keccak256( _finger) ) ].certUser = msg.sender;
        if (_revocationDate == 0) {
            self.certRevocations[ uint( keccak256( _finger) ) ].revocationDate = now;
        } else {
            self.certRevocations[ uint( keccak256( _finger) ) ].revocationDate = _revocationDate;
        }
        self.certRevocations[ uint( keccak256( _finger) ) ].loadDate = now;
        emit evRevokeCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 0, "");
    }

    // here _ind = getEvIndCertId(_finger), if success _hSha2 holds keccak256 of the certificate
    event evRevokeCertificateReturn(uint indexed _ind, int _err, string _errMsg);
    // here _ind = getEvIndSignId(_finger, _signedFinger)
    event evRevokeSigntReturn(uint indexed _ind, int _err, string _errMsg);

}
