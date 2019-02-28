pragma solidity ^0.4.22;
import "./corchestr.sol";
import "./ciden.sol";


library LIB_fingers {
    
    modifier checkRef(DaFingers storage self) {
        require(self.cOrchestrAddr != 0);
        _;
    }

    struct pgpFingers {
        bytes[] fingerList;
        uint loadDate;
    }

    // Here uint is keccak256(lower(email))
    // Any user can put some email into correspondance with a certificate
    // mapping to arrays https://ethereum.stackexchange.com/questions/1441/mapping-with-array-as-key-or-value-data-type
    struct DaFingers {
        mapping(uint => pgpFingers) fingers; /// !!!!
        address cOrchestrAddr;
        LU_PGP_orchestr cOrchestr;
        address cOridenAddr;
        LU_PGP_iden cOriden;

        //uint numErrLogs;
        //ErrLog[] errLogs;
    }

    /*struct ErrLog {
        bytes str;
        bytes32 uparam;
        bytes32 iparam;
        address addr;
        uint creationDate;
    }
    function newLog(DaFingers storage self, bytes _str, bytes32 _uparam, bytes32 _iparam, address _addr) public {
        ErrLog memory _reg;
        _reg.str = _str;
        _reg.uparam = _uparam;
        _reg.iparam = _iparam;
        _reg.addr = _addr;
        _reg.creationDate = now;
        self.errLogs.push(_reg);
        self.numErrLogs = self.errLogs.length;
    }
    function getLog(DaFingers storage self, uint _ind) external view returns(bytes, bytes32, bytes32) {
        return (self.errLogs[_ind].str, self.errLogs[_ind].uparam, self.errLogs[_ind].iparam);
    }*/


    function getOrchestrAddr(DaFingers storage self) external view returns(address) {
        return self.cOrchestrAddr;
    }

    function Init(DaFingers storage self, address _cOrchestrAddr, address _cOridenAddr) external //onlyOwner //setOrchestrAddr(_cOrchestrAddr)
    {
        self.cOrchestrAddr = _cOrchestrAddr; //already in modifier
        self.cOrchestr = LU_PGP_orchestr(self.cOrchestrAddr);

        self.cOridenAddr = _cOridenAddr; //already in modifier
        self.cOriden = LU_PGP_iden(self.cOridenAddr);
    }

    function newFinger(DaFingers storage self, string _email, bytes _finger) external {
        uint _flInd;
        int _err;
        uint _emailHash = uint( keccak256( bytes( lowerString(_email) ) ) );

        (_flInd, _err) = isFingersFinger( self, _email, _finger );
        if( _err == 1 ) {
            self.fingers[ _emailHash ].loadDate = now;
        }
        if( _err > 0 ) {
            self.fingers[ _emailHash ].fingerList.push(_finger);
        }
    }

    // returns err = 1 if there is no pgpFinger corresponding to that email
    function getFingersLen(DaFingers storage self, string _email)
                 external view checkRef(self) returns(uint len, int err)
    {
        uint _emailHash = uint( keccak256( bytes( lowerString(_email) ) ) );
        if( self.fingers[_emailHash].loadDate == 0 ) {
            return (0, 1);
        }
        return ( self.fingers[_emailHash].fingerList.length, 0 );
    }

    // _ind starts with 0
    //    err = 1, if _email does not corresponds any of the records
    //    err = 2, if _ind is out of the range
    function getFingersItem(DaFingers storage self, string _email, uint _ind)
                 external view checkRef(self) returns(bytes _res, int _err ) 
    { 
        uint _emailHash = uint( keccak256( bytes( lowerString(_email) ) ) );
        if( self.fingers[_emailHash].loadDate == 0 ) {
            return (_res, 1);
        }
        if( _ind >= self.fingers[_emailHash].fingerList.length ) {
            return (_res, 2);
        }
        return (self.fingers[_emailHash].fingerList[_ind], 0); 
    }

    // returns 
    //      _ind - index in corresponding fingerList
    //      _err = 1 if there is no fingerList corresponding to that email
    //      _err = 2 if there is no _finger in fingerList corresponding to that email
    function isFingersFinger(DaFingers storage self, string _email, bytes _finger)
                 public view checkRef(self) returns(uint _ind, int _err) 
    { 
        uint _emailHash = uint( keccak256( bytes( lowerString(_email) ) ) );
        if( self.fingers[_emailHash].loadDate == 0 ) {
            return (0, 1);
        }
        for(_ind=0; _ind < self.fingers[ _emailHash ].fingerList.length; _ind++){
            if ( keccak256( self.fingers[ _emailHash ].fingerList[_ind] )  == 
                        keccak256( _finger ) ) {
                return (_ind, 0);
            }
        }
        return (0, 2);
    }

    /*
        returns:
           0  - rights are OK
           1  - no certificate with this fimger
           2  - certificate's owner is not equal to _certUser
           3  - No fingerList is found for respective email
           4  - No finger is found in the fingerList for respective email
           6  - Param finger's length is not correct (not equals 20)
    */
    function checkRights(DaFingers storage self, bytes _finger, address _certUser)
                 public view checkRef(self) returns(int err, string errMsg) 
    {
        if (_finger.length != 20) {
            return (6, "Param finger's length is not correct (not equals 20)");
        }
        //if (identities[ uint( keccak256( _finger ) ) ].loadDate == 0) {
        if (self.cOriden.getIdenLoadDate(_finger) == 0) {
            return (1, "No identity is found for this fimger");
        }
        //if (identities[ uint( keccak256( _finger ) ) ].certUser != _certUser) {
        if (self.cOriden.getIdenCertUser( _finger ) != _certUser) {
            return (2, "Identity's user account is not equal to _certUser");
        }
        //string memory _email = identities[uint( keccak256( _finger ) )].email;
        string memory _email = self.cOriden.getIdenEmail( _finger );
        uint _fingerInd;
        int _err;
        (_fingerInd, _err) = isFingersFinger(self, _email, _finger);
        if (_err == 1) {
            return (3, "No fingerList is found for respective email");
        }
        if (_err > 1) {
            return (4, "No finger is found in the fingerList for respective email");
        }
        return (0, "");
    }

    /*
        returns are based on event:
           0  - success
           -1 - no Signature found
           1  - no Identy found
           6  - Param _finger has incorrect length (not equals 20)
           7  - Param _trustFinger has incorrect length (not equals 20)
    */
    function findSigntIndex( DaFingers storage self, bytes _finger, bytes _signedFinger) public view checkRef(self)
         returns(uint _ind, bytes _proposedCert, int _err, string _errMsg)
    {
        if (_finger.length != 20) {
            return (0, _proposedCert, 6, "Param _finger has incorrect length (not equals 20)");
        }
        if (_signedFinger.length != 20) {
            return (0, _proposedCert, 7, "Param _trustFinger has incorrect length (not equals 20)");
        }

        uint signLen;
        (signLen, _err) = self.cOriden.getSigntLen(_finger);
        if( _err!=0 ) {
            return (0, _proposedCert, 1, "No Identity found for _finger");
        }
        // identities[ uint( keccak256( _finger ) ) ].externSignts.length
        for(uint i = signLen; i>0; i--) {
            // identities[ uint( keccak256( _finger ) ) ].externSignts[i-1].finger
            bytes memory currSFinger;
            uint revokedDate;
            (currSFinger, _proposedCert, revokedDate, _err) = self.cOriden.getSignedFinger(_finger, i-1);
            if( revokedDate!=0 ) {
                continue;
            }
            if( uint(keccak256( currSFinger ) ) == uint(keccak256( _signedFinger) ) ) {
                return (i-1, _proposedCert, 0, "");
            }
        }
        return (0, _proposedCert, -1, "No Signature found for _finger");
    }


    function getSignRevokeInd(bytes _finger, uint _arrInd) public pure returns(uint) {
        bytes32 _byt32Ind = bytes32(_arrInd + 1);  // just to make Index start from 1, not 0
                
        uint BYTE_NUMBER = 4;
        bytes memory _bytInd = new bytes(BYTE_NUMBER);
        /*for (uint i = _byt32Ind.length - _bytInd.length - 1; i < _byt32Ind.length; i++) {
            _bytInd[j++] = _byt32Ind[i];
        }*/
        uint _minLength = _bytInd.length;
        if (_minLength > _byt32Ind.length) {
            _minLength = _byt32Ind.length;
        }
        for (uint i = 1; i <= _minLength; i++) {
            _bytInd[ _bytInd.length - i ] = _byt32Ind[ _byt32Ind.length - i ];
        }            
        return uint( keccak256( concateBytes( _finger, _bytInd ) ) );
    }

    function concateBytes(bytes _base, bytes _value) public pure returns (bytes) {
        bytes memory _newValue = new bytes(_base.length + _value.length);

        uint i;
        uint j;

        for(i=0; i<_base.length; i++) {
            _newValue[j++] = _base[i];
        }

        for(i=0; i<_value.length; i++) {
            _newValue[j++] = _value[i];
        }

        return _newValue;
    }

    function lowerString(string str) public pure returns (string) {
        bytes memory bStr = bytes(str);
        bytes memory bLower = new bytes(bStr.length);
        for (uint i = 0; i < bStr.length; i++) {
			// Uppercase character...
            if ((bStr[i] >= 65) && (bStr[i] <= 90)) {
				// So we add 32 to make it lowercase
                bLower[i] = bytes1(int(bStr[i]) + 32);
            } else {
                bLower[i] = bStr[i];
            }
        }
        return string(bLower);
    }

    // used for converting hashes to strings in event emitting (evCertNew) 
    function bytes32string(bytes32 b32) internal pure returns (string out) {
        bytes memory s = new bytes(64);
        for (uint i = 0; i < 32; i++) {
            byte b = byte(b32[i]);
            byte hi = byte(uint8(b) / 16);
            byte lo = byte(uint8(b) - 16 * uint8(hi));
            s[i*2] = char(hi);
            s[i*2+1] = char(lo);            
        }
        out = string(s);
    }
    function char(byte b) internal pure returns (byte c) {
        if (b < 10) return byte(uint8(b) + 0x30);
        else return byte(uint8(b) + 0x57);
    }

    function calcCertHash(bytes armoured) pure external returns(uint result) {
        byte brkChar = 0xA;
        uint leadBrkNum = 3;
        uint trailBrkNum = 2;

        uint jStart=0;        
        for (uint i = 0; i<leadBrkNum; i++) {
            for (; jStart < armoured.length; jStart++) {
                if ( armoured[jStart] == brkChar ) {
                    break;
                }
            }
            //newLog(DaFingers storage self, string _str, uint _uparam, uint _iparam, address _addr)
            if (jStart >= armoured.length) {
                return 0; // returns zero length 
            }
            if ( armoured[jStart] != brkChar ) {
                return 1; // returns zero length 
            }
            jStart = jStart + 1;
        }

        uint jFinish = armoured.length;
        for (i = 0; i<trailBrkNum; i++) {
            for (; jFinish>0; jFinish--) {
                if ( armoured[jFinish-1] == brkChar ) {
                    break;
                }
            }
            if (jFinish == 0) {
                return 3; // returns zero length 
            }
            if (armoured[jFinish-1] != brkChar) {
                return 4; // returns zero length
            }
            jFinish = jFinish-1;
        }

        if (jStart >= jFinish) {
            return 5; // returns zero length 
        }
        bytes memory extract = new bytes(jFinish - jStart);
        for (i = 0; i < extract.length; i++) {
            extract[i] = armoured[jStart+i];
        }
        return uint(sha256(extract));
    }

    /*
    // DEBUG
    function calcCertHash_1(DaFingers storage self, bytes armoured) external returns(uint result) {
        byte brkChar = 0xA;
        uint leadBrkNum = 3;
        uint trailBrkNum = 2;

        uint jStart=0;        
        for (uint i = 0; i<leadBrkNum; i++) {
            for (; jStart < armoured.length; jStart++) {
                if ( armoured[jStart] == brkChar ) {
                    break;
                }
            }
            //newLog(DaFingers storage self, string _str, uint _uparam, uint _iparam, address _addr)
            if (jStart >= armoured.length) {
                return 0; // returns zero length 
            }
            if ( armoured[jStart] != brkChar ) {
                return 1; // returns zero length 
            }
            jStart = jStart + 1;
        }

        uint jFinish = armoured.length;
        if (armoured[jFinish-1] == brkChar) {
            jFinish = jFinish - 1;
        }
        for (i = 0; i<trailBrkNum; i++) {
            for (; jFinish>0; jFinish--) {
                if ( armoured[jFinish-1] == brkChar ) {
                    break;
                }
            }
            if (jFinish == 0) {
                return 3; // returns zero length 
            }
            if (armoured[jFinish-1] != brkChar) {
                return 4; // returns zero length
            }
            jFinish = jFinish-1;
        }

        if (jStart >= jFinish) {
            return 5; // returns zero length 
        }
        bytes memory extract = new bytes(jFinish - jStart);
        for (i = 0; i < extract.length; i++) {
            extract[i] = armoured[jStart+i];
        }
        bytes32 resHash = keccak256(extract);
        bytes32 resHash2 = sha256(extract);
        //newLog( self, extract, resHash, resHash2, msg.sender );
        return uint(resHash);
    }
    */

    /*
    function extractCertFromArmored(bytes armoured) external pure returns (bytes extract) {
        byte brkChar = 0xA;
        uint leadBrkNum = 3;
        uint trailBrkNum = 2;
        extract = new bytes(0);

        uint jStart=0;
        
        for (uint i = 0; i<leadBrkNum; i++) {
            for (; jStart < armoured.length; jStart++) {
                if ( armoured[jStart] == brkChar ) {
                    break;
                }
            }
            //newLog(DaFingers storage self, string _str, uint _uparam, uint _iparam, address _addr)
            if (jStart >= armoured.length) {
                return extract; // returns zero length 
            }
            if ( armoured[jStart] != brkChar ) {
                return extract; // returns zero length 
            }
            jStart = jStart + 1;
        }

        uint jFinish = armoured.length;
        for (i = 0; i<trailBrkNum; i++) {
            for (; jFinish>0; jFinish--) {
                if ( armoured[jFinish-1] == brkChar ) {
                    break;
                }
            }
            if (jFinish == 0) {
                return extract; // returns zero length 
            }
            if (armoured[jFinish-1] != brkChar) {
                return extract; // returns zero length
            }
            jFinish = jFinish-1;
        }

        if (jStart >= jFinish) {
            return extract; // returns zero length 
        }
        extract = new bytes(jFinish - jStart);
        for (i = 0; i < extract.length; i++) {
            extract[i] = armoured[jStart+i];
        }
        return extract;
    }
    */

}
