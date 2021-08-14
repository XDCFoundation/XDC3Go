package XRC721
import (
    
	"fmt"
	"log"
	"strconv"
	"math/big"
	"context"
	"crypto/ecdsa"	
	"github.com/XDCFoundation/XDC3Go/common"
	"github.com/XDCFoundation/XDC3Go/crypto"
	"github.com/XDCFoundation/XDC3Go/core/types"  
    "github.com/XDCFoundation/XDC3Go/accounts/abi/bind"
	"golang.org/x/crypto/sha3"
)

    /**
     * @dev Gets the Name of the specified address.
     * @param tokenAddress 	The address of the token.
     * @return An String representing the Name owned by the passed address.
     */

func NameXRC721(tokenAddress string) string{
	
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }

// name calling
    name, err := instance.Name(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }
    return name
    }


    /**
     * @dev Gets the symbol of the specified address.
     * @param tokenAddress 	The address of the token.
     * @return An String representing the symbol owned by the passed address.
     */

func SymbolXRC721(tokenAddress string) string{
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	symbol, err := instance.Symbol(&bind.CallOpts{})
	if err != nil {
		log.Fatal(err)
	}
	return symbol

}

 /** @notice Count all NFTs assigned to an owner
     *  @dev NFTs assigned to the zero address are considered invalid, and this
     *  function throws for queries about the zero address.
     *  @param tokenAddress      An address for whom to query the balance
     *  @param ownerAddress      The address which owns the funds.
     *  @return The number of NFTs owned by `_owner`, possibly zero */

func BalanceXRC721(tokenAddress string , ownerAddress string)string{
    token_address:= common.HexToAddress(tokenAddress)
    owner_address:= common.HexToAddress(ownerAddress)

    
	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	bal, err := instance.BalanceOf(&bind.CallOpts{}, owner_address)
    if err != nil {
        log.Fatal(err)
    }

	return bal.String()
}

 /** @notice Find the owner of an NFT
     *  @dev NFTs assigned to zero address are considered invalid, and queries
     *  about them do throw.
     *  @param tokenAddress     An address for whom to query the balance
     *  @param tokenID      The identifier for an NFT
     *  @return The address of the owner of the NFT */



func OwnerXRC721(tokenAddress string , tokenID string) common.Address{
	tokenIDInteger:= new(big.Int)
	tokenIDInteger1, ok := tokenIDInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	owner, err := instance.OwnerOf(&bind.CallOpts{}, tokenIDInteger1)
    if err != nil {
        log.Fatal(err)
    }
	return owner
}

 /** @notice Query if an address is an authorized operator for another address
     *  @param tokenAddress     An address for whom to query the balance
     *  @param ownerAddress     The address which owns the funds.
     *  @param operatorAddress      The address that acts on behalf of the owner
     *  @return True if `_operator` is an approved operator for `_owner`, false otherwise */

func IsApprovedForAllXRC721(tokenAddress string ,ownerAddress string, operatorAddress string) bool{
    token_address:= common.HexToAddress(tokenAddress)
    owner_address:= common.HexToAddress(ownerAddress)
    operator_address:= common.HexToAddress(operatorAddress)
    instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	isApproved, err := instance.IsApprovedForAll(&bind.CallOpts{}, owner_address,operator_address)
    if err != nil {
        log.Fatal(err)
    }
	return isApproved

}

 /** @notice Query if a contract implements an interface
     *  @dev Interface identification is specified in XRC-165. This function
     *  uses less than 30,000 gas.
     *  @param tokenAddress     An address for whom to query the balance
     *  @param interfaceID      The interface identifier, as specified in XRC-165
     *  @return `true` if the contract implements `interfaceID` and
     *  `interfaceID` is not 0xffffffff, `false` otherwise */

func SupportInterfaceXRC721(tokenAddress string, interfaceID int) bool{
    token_address:= common.HexToAddress(tokenAddress)
    instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
    supportInterface, err := instance.SupportsInterface(&bind.CallOpts{}, toByteArray(interfaceID))
    if err != nil {
        log.Fatal(err)
    }
	return supportInterface

}


 /** @notice Get the approved address for a single NFT
     *  @dev Throws if `_tokenID` is not a valid NFT.
     *  @param tokenAddress     An address for whom to query the balance
     *  @param tokenID      The identifier for an NFT */

func GetApprovedXRC721(tokenAddress string, tokenID string) common.Address{
	tokenIDInteger:= new(big.Int)
	tokenIDInteger1, ok := tokenIDInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
	}
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	getApproved, err := instance.GetApproved(&bind.CallOpts{},tokenIDInteger1 )
    if err != nil {
        log.Fatal(err)
    }
	return getApproved
}

 /**@notice Count NFTs tracked by this contract
     * them has an assigned and queryable owner not equal to the zero address
     * @param tokenAddress      An address for whom to query the balance
     * @return A count of valid NFTs tracked by this contract, where each one of */

func TotalSupplyXRC721(tokenAddress string) string {
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	totalSupply, err := instance.TotalSupply(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }

	return (totalSupply.String())
}

 /** @notice A distinct Uniform Resource Identifier (URI) for a given asset.
     * @dev Throws if `_tokenID` is not a valid NFT. URIs are defined in RFC
     * 3986. The URI may point to a JSON file that conforms to the "XRC721 Metadata JSON Schema".
     */

func TokenURIXRC721(tokenAddress string, tokenID string) string{
	tokenIDInteger:= new(big.Int)
	tokenIDInteger1, ok := tokenIDInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
    token_address:= common.HexToAddress(tokenAddress)

	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	tokenURI, err := instance.TokenURI(&bind.CallOpts{},tokenIDInteger1)
    if err != nil {
        log.Fatal(err)
    }
	return tokenURI 
}

/** @notice Enumerate NFTs assigned to an owner
     *  @dev Throws if `_index` >= `balanceOf(_owner)` or if `_owner` is the zero address, representing invalid NFTs.
     *  @param tokenAddress     An address for whom to query the balance
     *  @param IndexNO      A counter less than `totalSupply()`
     *  @param ownerAddress     The address which owns the funds.
     *  @return The token identifier for the `_index`th NFT assigned to `_owner` */

func TokenOfOwnerByIndexXRC721(tokenAddress string, indexNo string, ownerAddress string) string{
	indexNoInteger:= new(big.Int)
	indexNoInteger1, ok := indexNoInteger.SetString(indexNo, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
    token_address:= common.HexToAddress(tokenAddress)
    owner_address:= common.HexToAddress(ownerAddress)


	instance, err := NewToken(token_address, ClientURL_())
    if err != nil {
        log.Fatal(err)
    }
	tokenOfOwnerByIndex, err := instance.TokenOfOwnerByIndex(&bind.CallOpts{},owner_address,indexNoInteger1)
    if err != nil {
        log.Fatal(err)
    }

	return (tokenOfOwnerByIndex.String())
}

// ---------------------------------------------------------------------------------------
// Write Operations

/** @notice Change or reaffirm the approved address for an NFT
     *  @dev The zero address indicates there is no approved address.
     *  Throws unless `msg.sender` is the current NFT owner, or an authorized
     *  operator of the current owner.
     *  @param privatekey     Owner Private key.
     *  @param tokenAddress An address for whom to query the balance
     *  @param spenderAddress    The address to transfer to
     *  @param gas_price      Gas price of contract.
     *  @param gas_limit      Gas Limit of Contract.
    
     *  @param tokenID The identifier for an NFT
     */

func ApproveXRC721(private_key string , token_address string,spenderAddress string,gas_price string,gas_limit string,tokenID string ) string{
	
	tokenIDInteger := new(big.Int)
	tokenIDInteger1, ok := tokenIDInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}

	gasPriceInteger := new(big.Int)
	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
    client:=ClientURL_()

    privateKey, err := crypto.HexToECDSA(private_key)
    if err != nil {
        log.Fatal(err)
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    
    value := big.NewInt(0) // in wei (0 
    
    toAddress := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("approve(address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    // paddedAddressfrom := common.LeftPadBytes(fromAddress.Bytes(), 32)
    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
   
    paddedAmount := common.LeftPadBytes(tokenIDInteger1.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)
    tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, finalGasPrice, data)
//The next step is to sign the transaction with the private key of the sender. The SignTx method requires the EIP155 signer, which we derive the chain ID from the client.
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err)
    }
//And finally, broadcast the transaction:
    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }

	return (signedTx.Hash().Hex())
}

//----------------------------------------------------------------

/** @notice Transfers the ownership of an NFT from one address to another address
     *  @dev This works identically to the other function with an extra data parameter,
     *  except this function just sets data to "".
     *  @param private_key    Owner Private key.
     *  @param token_address An address for whom to query the balance
     *  @param spenderAddress    The address to transfer to 
     *  @param gas_price      Gas price of contract.
     *  @param gas_limit      Gas Limit of Contract.
     *  @param tokenID      The identifier for an NFT
    */

func SafeTransferXRC721(private_key string,token_address string ,spenderAddress string ,gas_price string ,gas_limit string , tokenID string) string{

	
	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}

    client:=ClientURL_()

    privateKey, err := crypto.HexToECDSA(private_key)
    if err != nil {
        log.Fatal(err)
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    
    value := big.NewInt(0) // in wei (0 
    
    toAddress := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("safeTransferFrom(address,address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddressfrom := common.LeftPadBytes(fromAddress.Bytes(), 32)
    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
   
    paddedAmount := common.LeftPadBytes(amountInteger1.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
	var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddressfrom...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, finalGasPrice, data)
//The next step is to sign the transaction with the private key of the sender. The SignTx method requires the EIP155 signer, which we derive the chain ID from the client.
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err)
    }
//And finally, broadcast the transaction:
    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }

	return (signedTx.Hash().Hex())
}


//------------------------------------------------------------

 /** @notice Transfer ownership of an NFT -- THE CALLER IS RESPONSIBLE
     *  TO CONFIRM THAT `_to` IS CAPABLE OF RECEIVING NFTS OR ELSE
     *  THEY MAY BE PERMANENTLY LOST
     *  @dev Throws unless `msg.sender` is the current owner, an authorized
     *  operator, or the approved address for this NFT. Throws if `_from` is
     *  not the current owner. Throws if `_to` is the zero address. Throws if
     *  `_tokenID` is not a valid NFT.
     *  @param private_key    Owner Private key.
     *  @param token_address    An address for whom to query the balance
     *  @param spenderAddress    The address to transfer to
     *  @param gas_price      Gas price of contract.
     *  @param gas_limit      Gas Limit of Contract.
     *  @param tokenID The identifier for an NFT
     */

func TransferFromXRC721(private_key string ,token_address string ,spenderAddress string, gas_price string,gas_limit string ,tokenID string) string{

	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(tokenID, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}

    client:=ClientURL_()

    privateKey, err := crypto.HexToECDSA(private_key)
    if err != nil {
        log.Fatal(err)
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    
    value := big.NewInt(0) // in wei (0 
    
    toAddress := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("transferFrom(address,address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddressfrom := common.LeftPadBytes(fromAddress.Bytes(), 32)
    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
    paddedAmount := common.LeftPadBytes(amountInteger1.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
	var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddressfrom...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, finalGasPrice, data)
//The next step is to sign the transaction with the private key of the sender. The SignTx method requires the EIP155 signer, which we derive the chain ID from the client.
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err)
    }
//And finally, broadcast the transaction:
    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }
	return (signedTx.Hash().Hex())
}

 /** @notice Enable or disable approval for a third party ("operator") to manage
     *  all of `msg.sender`'s assets
     *  @dev Emits the ApprovalForAll event. The contract MUST allow
     *  multiple operators per owner.
     *  @param private_key    Owner Private key.
     *  @param token_address    An address for whom to query the balance
     *  @param spenderAddress    The address to transfer to
     *  @param gas_price      Gas price of contract.
     *  @param gas_limit      Gas Limit of Contract.
     *  @param boolValue    if the operator is approved, false to revoke approval */

func SetapprovalforallXRC721(private_key string,token_address string,spenderAddress string,gas_price string,gas_limit string,boolValue string) string{

	
	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(boolValue, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}

	
    client:=ClientURL_()

    privateKey, err := crypto.HexToECDSA(private_key)
    if err != nil {
        log.Fatal(err)
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)

    value := big.NewInt(0) // in wei (0 
    
    toAddress := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("setApprovalForAll(address,bool)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
   
     paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
   
     paddedAmount := common.LeftPadBytes(amountInteger1.Bytes(), 32)

    var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
    tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, finalGasPrice, data)
//The next step is to sign the transaction with the private key of the sender. The SignTx method requires the EIP155 signer, which we derive the chain ID from the client.
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err)
    }
//And finally, broadcast the transaction:
    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }
   return (signedTx.Hash().Hex())
}

