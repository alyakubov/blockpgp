pragma solidity ^0.4.22;

contract LU_PGP_base {
    constructor() public { owner = msg.sender; }
    address internal owner;

    function getOwner() external view returns(address) { return owner; }

    function setOwner(address _addr) external onlyOwner { owner = _addr; }

    /*
    We do not do archestration because each class has its own global cClass'es
     referencing addresses of the corresponding class
    We cannot make cClass'es variables as local memory variables of the smart contract's
     functions due to restriction of 16 on local variables number

    LU_PGP_orchestr internal cOrchestr;
    address internal cOrchestrAddr;
    function setOrchestr(address _addr) public onlyOwner { 
        cOrchestrAddr = _addr;
        cOrchestr = LU_PGP_orchestr(_addr);
    }
    modifier checkOrchestrRef {
        require(cOrchestr != 0);
        _;
    }
    */

    //LU_PGP_fingers internal cFingers;
    //LU_PGP_revoc internal cRevoc;
    //LU_PGP_ksrv internal cKsrv;
    //LU_PGP_iden internal cIden;
    //LU_PGP_utils internal cUtils;

    address internal cOrchestrAddr;
    function getOrchestrAddr() public view returns(address) {
        return cOrchestrAddr;
    }

    /*modifier setOrchestrAddr(address _cOrchestrAddr) {
        cOrchestrAddr = _cOrchestrAddr;
        _;
    }*/
    function Init(address _cOrchestrAddr) external onlyOwner //setOrchestrAddr(_cOrchestrAddr)
    {
        cOrchestrAddr = _cOrchestrAddr;
    }

    // This contract only defines a modifier but does not use
    // it - it will be used in derived main contracts.
    // The function body of the main contract is inserted where the special symbol
    // "_;" in the definition of a modifier appears.
    // If the owner calls this function, the function is executed
    // and otherwise, an exception is thrown.
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }


}
