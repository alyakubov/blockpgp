pragma solidity ^0.4.22;
import "./corchestr.sol";
import "./ciden.sol";


library LIB_ksrv {

    struct KsrvUpdate {
        address ksrvAddr;
        bytes ksrvInfo;
        bytes proposedCert;
        uint loadDate;
    }

    struct FingerKsrvUpdates {
        KsrvUpdate[] ksrvUpdates;
        uint loadDate;
    }

    struct DaKsrv {
        // Here uint is uint(keccak256(finger))
        // correspondance of a user to certificate
        mapping(uint => FingerKsrvUpdates) fingerKsrvUpdates; /// !!!!
        address cOrchestrAddr;
        LU_PGP_orchestr cOrchestr;
        address cOridenAddr;
        LU_PGP_iden cOriden;
    }
    function getOrchestrAddr(DaKsrv storage self) external view returns(address) {
        return self.cOrchestrAddr;
    }

    //LU_PGP_fingers internal cFingers;
    //LU_PGP_iden internal cIden;
    //Interf_iden internal cIden;
    function Init(DaKsrv storage self, address _cOrchestrAddr, address _cOridenAddr) public //onlyOwner //setOrchestrAddr(_cOrchestrAddr)
    {
        self.cOrchestrAddr = _cOrchestrAddr; //-- already in modifier
        self.cOrchestr = LU_PGP_orchestr(_cOrchestrAddr);

        self.cOridenAddr = _cOridenAddr; //-- already in modifier
        self.cOriden = LU_PGP_iden(_cOridenAddr);

        //cFingers = LU_PGP_fingers(cOrchestr.getFingersAddr());
        //cIden = Interf_iden(cOrchestr.getIdenAddr());
    }
    modifier checkRef(DaKsrv storage self) {
        require(self.cOrchestrAddr != 0);
        require(self.cOridenAddr != 0);
        //require(cFingers.getOrchestrAddr() == cOrchestrAddr);
        //require(cIden.getOrchestrAddr() == cOrchestrAddr);
        _;
    }


    // returns length of keysrv updates in a given identity
    // error:
    //     1 : no identity found for this fingerHash
    function getKsrvUpdateLen(DaKsrv storage self, bytes _finger) public view returns(uint len, int err) { 
        if (self.fingerKsrvUpdates[uint(keccak256(_finger))].loadDate == 0) {
            return (0, 1);
        }
        return (self.fingerKsrvUpdates[uint(keccak256(_finger))].ksrvUpdates.length, 0);
    }

    /*
        isFound: 0 - not found
                 1 - found in ksrv updates
                 2 - found in ownCert 
        _ind = +(index) in ksrvUpdates
        returns are not based on event:
           0  - success
           // -1 - no Signature found -- not using it
           1  - no Identy found
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _proposedCert is empty
    */
    function isKsrvCertFound( DaKsrv storage self, bytes _finger, bytes _proposedCert) public view checkRef(self)
             returns(uint isFound, uint _ind, int _err, string _errMsg)
    {
        if (_finger.length != 20) {
            return (0, 0, 6, "Param _finger has incorrect length (not equals 20)");
        }
        if (_proposedCert.length < 30) {
            return (0, 0, 7, "Param _proposedCert has incorrect length (too short  < 30)");
        }

        //if (identities[ uint( keccak256( _finger ) )].loadDate == 0) {
        //if (cPgp.getIdenLoadDate( _finger ) == 0) {
        //    return (0, 0, 1, "No Identity found for _finger");
        //}

        uint ksrvUpdLen;
        // identities[ uint( keccak256( _finger ) ) ].ksrvUpdates.length
        (ksrvUpdLen, _err) = getKsrvUpdateLen(self, _finger);
        if( _err != 0 ) {
            return (0, 0, 1, "No Identity found for _finger");
        }
        for(uint i = ksrvUpdLen; i > 0; i--) {
            // identities[ uint( keccak256( _finger ) ) ].ksrvUpdates[i-1].proposedCert
            bytes memory currPCert; 
            (currPCert, _err) = getKsrvUpdate(self, _finger, i-1);
            if( uint( keccak256( currPCert ) ) == uint( keccak256( _proposedCert ) ) ) {
                return (1, i-1, 0, "");
            }
        }
        // identities[ uint( keccak256( _finger ) ) ].ownCert
        if( uint(keccak256( self.cOriden.getIdenOwnCert(_finger) )) == uint(keccak256( _proposedCert ) ) ) {
            return (2, 0, 0, "");
        }
        //return (0, 0, -1, "No Signature found for _finger");
        return (0, 0, 0, ""); // not found
    }    

    //    error codes:
    //        1 -- no corresponding identity
    //        2 -- empty ksrv updates array. 
    //        3 -- no data for this _ind. 
    function getKsrvUpdate(DaKsrv storage self, bytes _finger, uint _ind ) public view 
                returns(bytes _proposedCert, int _err) 
    { 
        uint len; 
        (len, _err) = getKsrvUpdateLen( self, _finger );
        if (_err != 0) {
            return ( _proposedCert, 1);        
        }
        if ( len == 0) {
            return ( _proposedCert, 2);
        }
        if ( len-1 < _ind) {
            return ( _proposedCert, 3);
        }
        _proposedCert = self.fingerKsrvUpdates[uint(keccak256(_finger))].ksrvUpdates[_ind].proposedCert;
        return (_proposedCert, 0);
    }

    /*
        _ind = +(index) in ksrvUpdates
        returns are not based on event:
           0  - success, cert is put into keysrv update queue
           -1 - cert found in ksrv updates
           -2 - cert found in ownCert 
           1  - no Identy found
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _proposedCert is empty
    */
    function newKsrvUpdate(DaKsrv storage self, bytes _finger, bytes _ksrvInfo, bytes _proposedCert)
                 public checkRef(self)
    {
        int _err;
        uint _flInd;
        uint _ind;   // index in Sig List for the _finger
        string memory _errMsg;
        string memory _email;
        uint isFound;

        (isFound, _ind, _err, _errMsg) = isKsrvCertFound(self, _finger, _proposedCert);
        if( _err>0 ) {
            emit evNewKsrvUpdate( getEvIndKsrvUpdate(self, _finger, msg.sender), _err, _errMsg);
            return;
        }
        if (isFound == 1) {
            emit evNewKsrvUpdate( getEvIndKsrvUpdate(self, _finger, msg.sender), -1, "Certificate is found in ksrv updates");
            return;
        }
        if (isFound == 2) {
            emit evNewKsrvUpdate( getEvIndKsrvUpdate(self, _finger, msg.sender), -2, "Certificate is found in ownCert");
            return;
        }

        // identities[ uint( keccak256( _finger ) ) ].email
        _email = self.cOriden.getIdenEmail( _finger );

        (_flInd, _err) = self.cOrchestr.isFingersFinger(_email, _finger);
        if (_err != 0) {
            emit evNewKsrvUpdate( getEvIndKsrvUpdate(self, _finger, msg.sender), 2, "No finger in fingerList for this email");
            return;
        }
        /*(_err, _errMsg) = checkKsrvRights(msg.sender);
        if (_err != 0) {
            emit evNewKsrvUpdate( getEvIndSignId(_finger, _signedFinger), 10+_err, _errMsg);
            return;
        }*/
        KsrvUpdate memory _upd;
        _upd.ksrvAddr = msg.sender;
        _upd.ksrvInfo = _ksrvInfo;
        _upd.proposedCert = _proposedCert;
        _upd.loadDate = now;
        self.fingerKsrvUpdates[ uint( keccak256( _finger ) ) ].ksrvUpdates.push(_upd);
        emit evNewKsrvUpdate( getEvIndKsrvUpdate( self, _finger, msg.sender), 0, "");
        emit evProposeCertKsrv( self.cOrchestr.getEvIndCertId(_finger), self.cOrchestr.calcCertHash(_proposedCert), msg.sender);
    }

    function getEvIndKsrvUpdate( DaKsrv storage self, bytes finger, address ksrvAddr) internal view returns(uint) {
        return self.cOrchestr.getSignRevokeInd(finger, uint(ksrvAddr));
    }

    // here _ind = getEvIndKsrvUpdate(finger, ksrvAddr)
    event evNewKsrvUpdate(uint indexed _ind, int _err, string _errMsg);
    // here _ind = getEvIndCertId(_finger)
    event evProposeCertKsrv(uint indexed _fingerId, uint _hSha2, address _ksrvAddr);
}

