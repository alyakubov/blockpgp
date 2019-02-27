#!/bin/bash

outputPath=./scontract/binout
addrFile=addr.txt
addrLibFile=addrLib.txt
gethWDir=/home/alex/wrk/Eth_wrk


# prints the deployed SC address with the orchestration SET-function argument corresponding to this SC 
# Parameters:
#          $1 -- file template (equals to the name of the corresponding smart contract)
#          $2 -- the address
# Returns:
#          0 -- ok
#          101 -- invalid SC_ID option for print_addr func
#          $? in case of other errors
#print_addr() {
#    case $1 in 
#    "LU_PGP") 
#        addrOrchestr=$2
#        echo "_cPgpAddr: $2," >> "$outputPath/$addrFile"
#        ;;
#    "LU_PGP_fingers") 
#        echo "_cFingersAddr: $2," >> "$outputPath/$addrFile";;
#    "LU_PGP_revoc") 
#        echo "_cRevocAddr: $2," >> "$outputPath/$addrFile";;
#    "LU_PGP_ksrv") 
#        echo "_cKsrvAddr: $2," >> "$outputPath/$addrFile";;
#    "LU_PGP_iden") 
#        echo "_cIdenAddr: $2," >> "$outputPath/$addrFile";;
#    "LU_PGP_utils") 
#        echo "_cUtilsAddr: $2," >> "$outputPath/$addrFile";;
#    *) 
#        echo "$1 -- invalid SC_ID option for print_addr func"
#        return 101
#        ;;
#    esac
#}

# Relinks libraries to the file with 
# Parameters:
#          $1 -- file template (equals to the name of the corresponding smart contract)
#          $2 -- path to the folder with bin files and abi files
# Returns:
#          0 -- ok
#          101 if bin file does not exist
#          102 if lib address file does not exist ("$outputPath/$addrLibFile")
#          $? in case of other errors
#relink_libs() {
#    local binfile=$1.bin
#    if [ ! -f "$2/$binfile" ] ; then
#        printf "File not found: %s\n" "$2/$binfile"
#        return 101
#    fi
#    if [ ! -f "$2/$binfile" ] ; then
#        printf "File with lib addresses for linkage is not found: %s\n" "$outputPath/$addrLibFile"
#        return 102
#    fi
    ###solc --bin MetaCoin.sol | solc --link --libraries TestLib:<address>
    #cat "$2/$binfile" | solc --link --libraries "$outputPath/$addrLibFile"
    #return $?
#}


# Deploys smart contract
# Parameters:
#          $1 -- file template (equals to the name of the corresponding smart contract)
#          $2 -- path to the folder with bin files and abi files
# Returns:
#          0 -- ok
#          101 if bin file does not exist
#          102 if abi file does not exist
#          $? in case of other errors
deploy_sc() {
    local abifile=$1.abi
    if [ ! -f "$2/$abifile" ] ; then
        printf "File not found: %s\n" "$2/$abifile"
        return 102
    fi
    local binfile=$1.bin
    if [ ! -f "$2/$binfile" ] ; then
        printf "File not found: %s\n" "$2/$binfile"
        return 101
    fi
    local abifilecontent=$(cat $2/$abifile)
    local binfilecontent=$(cat $2/$binfile)
    #echo "$binfilecontent"
    #echo "END"
    cat > ./tmpscript.js << EOF 
    chContract = eth.contract( $abifilecontent )
    personal.unlockAccount(eth.accounts[0],"ira")
    ch1 = chContract.new({
            from:web3.eth.accounts[0],
            data:'0x$binfilecontent',
            gas: 50000000
        }, function(e, contract){
            if(!e) {
                receipt = web3.eth.getTransactionReceipt(contract.transactionHash);
                            while (!(receipt && receipt.contractAddress)) {
                                    receipt = web3.eth.getTransactionReceipt(contract.transactionHash);
                    admin.sleep(1);
                            }
                            console.log(receipt.contractAddress);
            } else {
                console.log(e);
            }
        }
    )

EOF
    echo "Starting geth..." 
    local address=$(geth --exec 'loadScript("./tmpscript.js")' attach ipc:"$gethWDir"/geth.ipc 2> /dev/null | grep "^0x")
    #if ["$?" -ne 0] ; then  ## ERROR CHECK !!!
    #   return $?
    #fi
    local isLib=${binfile##*LIB}
    if [ "$isLib" = "$binfile" ]; then
        echo "$1:$address" >> "$outputPath/$addrFile"
    else
        echo "Saving to library address file"
        echo "$1:$address" >> "$outputPath/$addrLibFile"
    fi
    echo "Address $1: " $address
    #echo "$address" >> "$outputPath/$addrFile"
    #print_addr $1 $address
    return $?
}

# calls Init of the given SC with the orchestr address
# Parameters:
#          $1 -- string of X:Y
#              X = file template (equals to the name of the corresponding smart contract)
#              Y = address of this smart contract
#          $2 -- address of orchestr smart contract address (to be added to all smart contract through the Init func)
# Returns:
#          0 -- ok
#          101 if abi file file does not exist
init_sc() {
    local scParam=$1
    local scName=${scParam%:*}
    local scAddr=${scParam##*:}
    local cOrchestrAddr=$2
    local abiFile="$outputPath/$scName.abi"
    if [ ! -f "$abiFile" ] ; then
        printf "PGP smart contract abi file not found: %s\n" "$abiFile"
        return 101
    fi
    local abiFileContent=$(cat "$abiFile")
    cat > ./tmpinit.js << EOF 
    pgpContr = eth.contract( $abiFileContent )
    pgp = pgpContr.at( "$scAddr" )
    personal.unlockAccount(eth.accounts[0],"ira")
    pgp.Init.sendTransaction( "$cOrchestrAddr",
        {
            from:web3.eth.accounts[0], gas: 50000000
        }, function(e, contract){
            if(!e) {
                console.log("SUCCESS");
            } else {
                console.log(e);
            }
        }
    )

EOF
    printf "Starting init with %s ... " "$cOrchestrAddr"
    local res=$(geth --exec 'loadScript("./tmpinit.js")' attach ipc:"$gethWDir"/geth.ipc 2> /dev/null)
    echo "Smart Contract $scName init with orchestration address: $res"
    #echo "$address" >> "$outputPath/$addrFile"
    return $?

}

# Provides the update of Orchestration SC amd other SC with orchestr addr
# No parameters are required
# Returns:
#          0 -- ok
#          101 if address file does not exist
#          102 if orchestr sc abi file does not exist
#          $? in case of other errors
update_orchestr() {
    if [ ! -f "$outputPath/$addrFile" ] ; then
        printf "Address file not found: %s\n" "$outputPath/$addrFile"
        return 101
    fi
    local tmp=$(grep LU_PGP_orchestr $outputPath/$addrFile)
    local cOrchestrAddr=${tmp##*:}
    local tmp=$(grep LU_PGP_iden $outputPath/$addrFile)
    local cIdenAddr=${tmp##*:}
    if [ ! -f "$outputPath/LU_PGP_orchestr.abi" ] ; then
        printf "PGP orchestr abi file not found: %s\n" "$outputPath/LU_PGP_orchestr.abi"
        return 102
    fi
    local abiOrchestr=$(cat $outputPath/LU_PGP_orchestr.abi)
    cat > ./tmporchestr.js << EOF 
    orchContr = eth.contract( $abiOrchestr )
    orch = orchContr.at( "$cOrchestrAddr" )
    personal.unlockAccount(eth.accounts[0],"ira")
    orch.InitOrchestr.sendTransaction( "$cOrchestrAddr", "$cIdenAddr",
        {
            from:web3.eth.accounts[0], gas: 50000000
        }, function(e, contract){
            if(!e) {
                console.log("SUCCESS");
            } else {
                console.log(e);
            }
        }
    )

EOF
    echo "Starting orchestr update ..." 
    local res=$(geth --exec 'loadScript("./tmporchestr.js")' attach ipc:"$gethWDir"/geth.ipc 2> /dev/null)
    echo "Orchestration update: $res"
    #echo "$address" >> "$outputPath/$addrFile"

    for sc in "LU_PGP_iden:$cIdenAddr" #"LU_PGP_fingers:$cFingersAddr" "LU_PGP_revoc:$cRevocAddr" "LU_PGP_ksrv:$cKsrvAddr"
    do
        init_sc $sc $cOrchestrAddr
    done
    return $?

}

file_proc() {
    local i=$1
    if [ -f "$i" ]; then
        printf "Full path name: %s\n" $i
        ## bash shell parameter expansion
        local filePath=${i%/*}
        printf "Path: %s\n" $filePath # shortest suffix removal
        local fileName=${i##*/}
        printf "Filename: %s\n" $fileName # longest prefix removal
        printf "Extension: %s\n" ${i##*.}
        local fileTemplate=${fileName%.*}
        printf "Filename w/o extensions: %s\n" $fileTemplate
        printf "Filesize: %s\n" "$(du -b "$i" | awk '{print $1}')"

        deploy_sc "$fileTemplate" "$filePath"
        # deployment error check should be added here
    else
        printf "cannot find i: %s\n" $i
    fi
}

# Returns:
#       0: SUCCESS
#       1: ERROR - the lib address file was not created
main() {
    solc --bin --overwrite -o ./scontract/binout ./scontract/corchestr.sol
    solc --abi --overwrite -o ./scontract/binout ./scontract/corchestr.sol

    ##solc --bin MetaCoin.sol | solc --link --libraries TestLib:<address>

    if [ -f "$outputPath/$addrFile" ] ; then
        printf "removing address file %s..." "$outputPath/$addrFile"
        rm "$outputPath/$addrFile"
        printf "OK\n"
    fi
    if [ -f "$outputPath/$addrLibFile" ] ; then
        printf "removing address lib file %s..." "$outputPath/$addrLibFile"
        rm "$outputPath/$addrLibFile"
        printf "OK\n"
    fi
    local libs="$outputPath/LIB_*.bin"
    local libIterator
    for libIterator in $libs; do
        file_proc $libIterator
    done

    if [ -f "$outputPath/$addrLibFile" ] ; then
        printf "Relinking libs to smart contract %s..." "$outputPath/$addrFile"
        solc ./scontract/corchestr.sol --bin --overwrite -o ./scontract/binout --libraries "$outputPath/$addrLibFile"
        printf "OK\n"
    else
        echo "No lib address file is found"
        return 1
    fi

    
    local files="$outputPath/LU_PGP_*.bin"
    local fileIterator
    for fileIterator in $files; do
        file_proc $fileIterator
    done
    update_orchestr

    return 0
}

main

