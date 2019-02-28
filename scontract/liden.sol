pragma solidity ^0.4.22;
import "./corchestr.sol";

library LIB_iden {

    struct pgpIdentity {
        bytes ownCert;
        string name;
        string email;
        pgpSignt[] externSignts;
        uint loadDate;
        address certUser;
    }
    struct pgpSignt {
        bytes finger;
        bytes proposedCert;
        uint loadDate;
    }

    /*struct ErrLog {
        string str;
        uint uparam;
        uint iparam;
        address addr;
        uint creationDate;
    }
    function newLog(DaIden self, string _str, uint _uparam, uint _iparam, address _addr) internal {
        uint _logId = self.errLogs.length++;
        ErrLog storage _reg = self.errLogs[_logId];
        _reg.str = _str;
        _reg.uparam = _uparam;
        _reg.iparam = _iparam;
        _reg.addr = _addr;
        _reg.creationDate = now;
        self.numErrLogs = _logId + 1;
    }*/
    // Here uint is uint(keccak256(finger))
    // correspondance of a user to certificate
    struct DaIden {
        mapping(uint => pgpIdentity) identities; /// !!!!
        address cOrchestrAddr;
        LU_PGP_orchestr cOrchestr;

        //uint numErrLogs;
        //ErrLog[] errLogs;
    }
    function getOrchestrAddr(DaIden storage self) external view returns(address) {
        return self.cOrchestrAddr;
    }

    /*LU_PGP_fingers internal cFingers;
    LU_PGP_revoc internal cRevoc;
    LU_PGP_ksrv internal cKsrv;*/
    function Init(DaIden storage self, address _cOrchestrAddr) external //onlyOwner //setOrchestrAddr(_cOrchestrAddr)
    {
        self.cOrchestrAddr = _cOrchestrAddr; //-- already in modifier

        self.cOrchestr = LU_PGP_orchestr(self.cOrchestrAddr);
        /*address tmpAddr = cOrchestr.getFingersAddr();
        cFingers = LU_PGP_fingers(tmpAddr);
        tmpAddr = cOrchestr.getRevocAddr();
        cRevoc = LU_PGP_revoc(tmpAddr);
        tmpAddr = cOrchestr.getKsrvAddr();
        cKsrv = LU_PGP_ksrv(tmpAddr);*/
    }
    modifier checkRef(DaIden storage self) {
        require(self.cOrchestrAddr != 0);
        /*require(cFingers.getOrchestrAddr() == cOrchestrAddr);
        require(cRevoc.getOrchestrAddr() == cOrchestrAddr);
        require(cKsrv.getOrchestrAddr() == cOrchestrAddr);*/
        _;
    }


    function getIdenOwnCert(DaIden storage self, bytes _finger) external view returns(bytes) { 
        return self.identities[uint(keccak256(_finger))].ownCert; 
    }
    function getIdenLoadDate(DaIden storage self, bytes _finger) external view returns(uint) { 
        return self.identities[uint(keccak256(_finger))].loadDate;
    }
    function getIdenEmail(DaIden storage self, bytes _finger) external view returns(string) { 
        return self.identities[uint(keccak256(_finger))].email;
    }
    function getIdenName(DaIden storage self, bytes _finger) external view returns(string) { 
        return self.identities[uint(keccak256(_finger))].name;
    }
    function getIdenCertUser(DaIden storage self, bytes _finger) external view returns(address) { 
        return self.identities[uint(keccak256(_finger))].certUser;
    }

    // returns length of trust in a given identity (including revoked trusts)
    // error:
    //     1 : no identity found for this fingerHash
    function getSigntLen(DaIden storage self, bytes _finger) external view returns(uint len, int err) { 
        if (self.identities[uint(keccak256(_finger))].loadDate == 0) {
            return (0, 1);
        }
        return (self.identities[uint(keccak256(_finger))].externSignts.length, 0);
    }

    //    error codes:
    //        1 -- no corresponding identity
    //        2 -- empty signt array
    //        3 -- no data found fr this _ind
    function getSignedFinger(DaIden storage self, bytes _finger, uint _ind ) external view checkRef(self)
                returns(bytes _signedFinger, bytes _proposedCert, uint _revocationDate, int _err) 
    { 
        uint len;
        bool isRevoc;

        //(len, _err) = getSigntLen(_finger);
        if (self.identities[uint(keccak256(_finger))].loadDate == 0) {
            return (_signedFinger, "", 0, 1);
        }
        len = self.identities[uint(keccak256(_finger))].externSignts.length;
        if (len == 0) {
            return (_signedFinger, "", 0, 2);
        }
        if (len-1 < _ind) {
            return (_signedFinger, "", 0, 3);
        }
        _signedFinger = self.identities[uint(keccak256(_finger))].externSignts[_ind].finger;
        _proposedCert = self.identities[uint(keccak256(_finger))].externSignts[_ind].proposedCert;
        // cRevoc.signtRevocations[ cOrchestr.getSignRevokeInd( _finger , _ind ) ].revocationDate
        ( isRevoc, _revocationDate ) = self.cOrchestr.getSigntRevocation( _finger, _ind );
        _err = 0;
        return (_signedFinger, _proposedCert, _revocationDate, _err);
    }


    // here _ind = getEvIndCertId(_finger)
    // code: 1 - new cert, 
    //       2 - cert update by owner, 
    //       3 - cert update by admin
    //       4 - cert accepted from signature queue, emitted by AcceptCertSignature
    //       5 - cert accepted from key server updates, emitted by AcceptCertKsrv
    event evNewCertificateAnnounce(bytes _finger, bytes _armoured, uint _code);
    
    // here _ind = getEvIndCertId(_finger), if success _hSha2 holds Sha256 of the certificate
    event evNewCertificateReturn(uint indexed _ind, int _err, string _errMsg, uint _hSha2);
    // here _ind = getEvIndSignId(_finger, _signedFinger)
    event evNewSigntReturn(uint indexed _ind, int _err, string _errMsg);

    event evProposeCertSignature(address indexed _toUser, bytes _finger, bytes _signedFinger,
         uint _hSha2, address _fromUser);
    // here _ind = getEvIndSignId(_introducedFinger, finger)
    event evAcceptedCertSignature(uint indexed _ind, int _err, string _errMsg, uint _hSha2);

    // here _ind = getEvIndCertId(_finger)
    event evAcceptedCertKsrv(uint indexed _ind, int _err, string _errMsg, uint _hSha2);


    //function getEthHash(bytes _data) public pure returns(uint) {return uint(keccak256(_data));}


    /*  
        returns are based on event:
           -10 - user has no rights -- STRANGE ERROR
           -3 - param _finger length is incorrect (not equals 20)
           -2 - msg.sender != owner
           -1 - msg.sender != _certUser -- User has no rights
           0  - certificate and identity are successfully added
           1  - just certificate added, update in identity because it is updated by legal user
           2  - just certificate added, update in identity because it is updated by admin
           3  - OUTDATED -- just certificate added, no update in identity because the user has no rights to do it 
    */
    function newCertificate(DaIden storage self, string _email, bytes _finger, bytes _ownCert,
                 string _name, address _certUser ) external checkRef(self)
    {
        // IMPORTANT -- _certUser != owner of the contract
        if (_finger.length != 20) {
            emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId(_finger ), -3, 
                "param _finger length is incorrect (not equals 20)", 0);
            return;
        }

        if ( msg.sender != self.cOrchestr.getOwner() ) {
            if (_certUser != msg.sender) {
                emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId( _finger ), -1, "User has no rights", 0);
                return;
            }
        } else if (self.cOrchestr.getOwner() == _certUser) {
            emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId( _finger ), -2, "certUser should be != owner", 0);
            return;
        }

        self.cOrchestr.newFinger( _email, _finger );

        uint certHash = self.cOrchestr.calcCertHash(_ownCert);

        if (self.identities[ uint( keccak256( _finger ) ) ].loadDate == 0) {
            insertIdentity(self, _finger, _ownCert, _name, _email, msg.sender);
            emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId( _finger), 0, "", certHash);
            emit evNewCertificateAnnounce( _finger, _ownCert, 1);
        } else { 
            if ( self.identities[ uint( keccak256( _finger ) ) ].certUser == msg.sender) {
                insertIdentity(self, _finger, _ownCert, _name, _email, msg.sender);
                emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 1, 
                    "Update in identity because it is updated by legal user", certHash);
                emit evNewCertificateAnnounce( _finger, _ownCert, 2);
            } else {
                if ( self.cOrchestr.getOwner() == msg.sender ) {
                    insertIdentity(self, _finger, _ownCert, _name, _email, _certUser);
                    emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), 2, 
                        "Update in identity because it is updated by admin", certHash);
                    emit evNewCertificateAnnounce( _finger, _ownCert, 3);
                } else {
                    emit evNewCertificateReturn( self.cOrchestr.getEvIndCertId(_finger), -10,
                        "STRANGE ERROR - user has no rights", 0);
                }
            }
        }
    }

    function insertIdentity(DaIden storage self, bytes _finger, bytes _ownCert,
             string _name, string _email, address _certUser) internal 
    {
        self.identities[ uint( keccak256( _finger ) )].ownCert = _ownCert;
        self.identities[ uint( keccak256( _finger ) )].name = _name;
        self.identities[ uint( keccak256( _finger ) )].email = _email;
        self.identities[ uint( keccak256( _finger ) )].certUser = _certUser;
        self.identities[ uint( keccak256( _finger ) )].loadDate = now;
    }


    /*
        returns are not based on event:
           0  - success, cert is put into keysrv update queue
           1  - no ksrvUpdates are found corresponding to the _proposedCert
           2  - proposedCert is already updated 
           10 + checkRight's err 
           20 + isKsrvCertFound's err
    */
    function acceptKsrvUpdate( DaIden storage self, bytes _finger, bytes _proposedCert ) external checkRef(self) {

        uint _ind;
        uint _isFound;
        int _err;
        string memory _errMsg;

        (_err, _errMsg) = self.cOrchestr.checkRights(_finger, msg.sender);
        if (_err != 0) {
            emit evAcceptedCertKsrv( self.cOrchestr.getEvIndCertId(_finger), 10+_err, _errMsg, 0);
            return;
        }

        (_isFound, _ind, _err, _errMsg) = self.cOrchestr.isKsrvCertFound(_finger, _proposedCert);
        if( _err != 0 ) {
            emit evAcceptedCertKsrv( self.cOrchestr.getEvIndCertId(_finger), 20+_err, "Error in getKsrvUpdates - no ksrv update", 0);
            return;
        }
        if( _isFound == 0 ) {
            emit evAcceptedCertKsrv( self.cOrchestr.getEvIndCertId(_finger), 1, "No ksrvUpdates are found", 0);
            return;
        }
        if( _isFound == 2 ) {
            emit evAcceptedCertKsrv( self.cOrchestr.getEvIndCertId(_finger), 2, "proposedCert is already updated", 0);
            return;
        }

        uint hash = self.cOrchestr.calcCertHash( _proposedCert );
        self.identities[ uint( keccak256( _finger ) ) ].ownCert = _proposedCert;
        emit evAcceptedCertKsrv( self.cOrchestr.getEvIndCertId(_finger) , 0, "", hash );
        emit evNewCertificateAnnounce( _finger, _proposedCert, 5);
    }

    /*  
        finger = introducing finger
        signed finger = finger which was signed
        _email can be empty - in this case we take email from the _finger's identity
        !!! Event is sent to hint to the certificate owner that there is new sig and proposed cert
        returns are based on event:
           0  - success
           1  - No Identy found for _finger
           2  - No finger in fingerList for this email
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _trustFinger has incorrect length (not equals 20)
           8  - 
           11-19 - checkRights errors
    */
    function newSignt(DaIden storage self, bytes _finger, bytes _signedFinger, bytes _proposedCert) external checkRef(self) 
    {
        int _err;
        uint _ind;   // index in Sig List for the _finger
        bool isFound;

        string memory _errMsg;
        bytes memory _currPCert;

        (_ind, _currPCert, _err, _errMsg) = self.cOrchestr.findSigntIndex(_finger, _signedFinger);
        if( _err>0 ) {
            emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), _err, _errMsg);
            return;
        }
        if (_err == 0) {
            if( uint(keccak256(_currPCert)) == uint(keccak256(_proposedCert)) ){  //?? Replace with two getCertHash calls?
                emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 8,
                     "Proposed cert param equals existing proposed cert");
                return;
            }
            isFound = true; 
        }

        /*(_ind, isFound, _err) = findSignt(self, _finger, _signedFinger, _proposedCert);
        if (_err > 0) {
            return;
        }
        if (_err == 2) {
            return;
        }*/

        insertSignt(self, _finger, _signedFinger, _proposedCert, _ind, isFound);
    }

    /* returns:
            _ind - index in Sig List for the _finger
           0  - success
           -2 - Proposed cert param equals existing cert (hash for FULL!! certificate)
           -1 - no Signature found
           1  - no Identy found
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _trustFinger has incorrect length (not equals 20)
    */ 
    /*function findSignt(DaIden storage self, bytes _finger, bytes _signedFinger, bytes _proposedCert) internal
             returns(uint _ind, bool isFound, int _err)
    {
        //uint _ind;   // index in Sig List for the _finger
        string memory _errMsg;
        bytes memory _currPCert;

        (_ind, _currPCert, _err, _errMsg) = self.cOrchestr.findSigntIndex(_finger, _signedFinger);
        if( _err>0 ) {
            emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), _err, _errMsg);
            return (0, false, _err);
        }
        if (_err == 0) {
            if( uint(keccak256(_currPCert)) == uint(keccak256(_proposedCert)) ){  //?? Replace with two getCertHash calls?
                emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 8,
                     "Proposed cert param equals existing proposed cert");
                return (0, false, -2);
            }
            isFound = true; 
        }
        return (_ind, isFound, 0);
    }*/

    /*
        returns are based on event:
           0  - success
           2  - No finger in fingerList for this email
           11-19 - checkRights errors
    */
    function insertSignt(DaIden storage self, bytes _finger, bytes _signedFinger,
             bytes _proposedCert, uint _ind, bool _isFound) internal // returns(int _err)
    {
        int _err;
        uint _flInd;
        string memory _email;
        string memory _errMsg;

        _email = self.identities[ uint( keccak256( _finger ) ) ].email;

        (_flInd, _err) = self.cOrchestr.isFingersFinger( _email, _finger);
        if (_err != 0) {
            emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger),
                     2, "No finger in fingerList for this email");
            return; // _err;
        }
        (_err, _errMsg) = self.cOrchestr.checkRights(_finger, msg.sender);
        if (_err != 0) {
            emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 10+_err, _errMsg);
            return; // (10 + _err);
        }

        pgpSignt memory _signt;
        _signt.finger = _signedFinger;
        _signt.proposedCert = _proposedCert;
        _signt.loadDate = now;
        if( _isFound == false ) {  // No signature found
            self.identities[ uint( keccak256( _finger ) ) ].externSignts.push(_signt);
        } else {
            self.identities[ uint( keccak256( _finger ) ) ].externSignts[_ind] = _signt;
        }
        emit evNewSigntReturn( self.cOrchestr.getEvIndSignId(_finger, _signedFinger), 0, "");
        emit evProposeCertSignature( self.identities[ uint( keccak256( _signedFinger ) ) ].certUser/*_toUser*/,
                _finger,  _signedFinger, self.cOrchestr.calcCertHash(_proposedCert), msg.sender);
        return; // 0;
    }


    function acceptProposedCert(DaIden storage self, bytes _introducingFinger, bytes _finger) external checkRef(self) {
        uint _ind;
        int _err;
        bytes memory _proposedCert;
        string memory _errMsg;

        (_err, _errMsg) = self.cOrchestr.checkRights(_finger, msg.sender);
        if (_err != 0) {
            emit evAcceptedCertSignature( self.cOrchestr.getEvIndSignId(_introducingFinger, _finger), 10+_err, _errMsg, 0);
            return;
        }
        (_ind, _proposedCert, _err, _errMsg) = self.cOrchestr.findSigntIndex(_introducingFinger, _finger );
        if( _err != 0 ) {
            emit evAcceptedCertSignature( self.cOrchestr.getEvIndSignId(_introducingFinger, _finger), _err, _errMsg, 0);
            return;
        }

        uint hash = self.cOrchestr.calcCertHash(_proposedCert);
        self.identities[ uint( keccak256( _finger ) ) ].ownCert =_proposedCert;
        emit evAcceptedCertSignature( self.cOrchestr.getEvIndSignId(_introducingFinger, _finger), 0, "", hash);
        emit evNewCertificateAnnounce( _finger, _proposedCert, 4);
    }

}

