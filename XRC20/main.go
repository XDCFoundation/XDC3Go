package XRC20
import (
    "log"
    "fmt"
	"github.com/XDCFoundation/XDC3Go/common"
	"math/big"
	"strconv"
	"math"
	"crypto/ecdsa"
	"context"
	"encoding/hex"
	"github.com/XDCFoundation/XDC3Go/rlp"
	"golang.org/x/crypto/sha3"
	"github.com/XDCFoundation/XDC3Go/common/hexutil"
	"github.com/XDCFoundation/XDC3Go/crypto"
	"github.com/XDCFoundation/XDC3Go/core/types"
	"github.com/XDCFoundation/XDC3Go/accounts/abi/bind"
   
)


	/**
     * @dev Gets the Decimal of the specified address.
     * @param token_address The address of the token.
     * @return An String representing the Decimal owned by the passed address.
     */

func DecimalsXRC20(token_address string) uint8{
	tokenAddress := common.HexToAddress(token_address)// token address
	instance, err := NewToken(tokenAddress, ClientURL_())

	decimals, err := instance.Decimals(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }
	
		return decimals
}


 	/**
     * @dev Gets the balance of the specified address.
     * @param token_address The address of the token.
     * @param owner_address The address to query the balance of.
     * @return An String representing the amount owned by the passed address.
     */
func BalanceXRC20(token_address string ,owner_address string) string{
	tokenAddress := common.HexToAddress(token_address)// token address
	ownerAddress := common.HexToAddress(owner_address)// Owner address

	instance, err := NewToken(tokenAddress, ClientURL_())
	if err != nil {
        
		log.Fatal(err)
	}
	balance, err := instance.BalanceOf(&bind.CallOpts{},ownerAddress)
    if err != nil {
        log.Fatal(err)
    }
	bal_in_float := new(big.Float) // declare float balance variable.
    bal_in_float.SetString(balance.String()) 
    quoBalance := new(big.Float).Quo(bal_in_float, big.NewFloat(math.Pow10(int(DecimalsXRC20(token_address)))))
//----------------------- for balance calculation
	float_balance, err := strconv.ParseFloat(quoBalance.String(), 64) // stringBalance coonvert in flloat64
	var newFloatBalance float64 =float64(float_balance) // assign float_balance in new variable which type float64
	var bal_in_string string = strconv.FormatFloat(newFloatBalance, 'E', -1, 32) // converting ballance from float to string (e+9).
	finalBalance, _, err := big.ParseFloat(bal_in_string, 10, 0, big.ToNearestEven) // final ballance
	if err != nil {
		panic(err)
	}
	var finalbal_in_int = new(big.Int)
	finalbal_in_int, acc := finalBalance.Int(finalbal_in_int)
	fmt.Println(acc)
	return (new(big.Int).Div(finalbal_in_int, DividendData()).String())

}

	/**
     * @dev Gets the Name of the specified address.
     * @param token_address 	The address of the token.
     * @return An String representing the Name owned by the passed address.
     */

func NameXRC20(token_address string)string {
	tokenAddress := common.HexToAddress(token_address)// token address
	instance, err := NewToken(tokenAddress, ClientURL_())
	if err != nil {
        
		log.Fatal(err)
	}
	name, err := instance.Name(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }
	return name
}

/**
*
@param token_address The address of the token.
@return the symbol of the token.
*/

func SymbolXRC20(token_address string)string {
	tokenAddress := common.HexToAddress(token_address)// token address
	instance, err := NewToken(tokenAddress, ClientURL_())
	if err != nil {
        
		log.Fatal(err)
	}
	symbol, err := instance.Symbol(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }
	return symbol
}

/**
     * @dev Gets the Totalsupply of the specified address.
     * @param token_address 	The address of the token.
     * @return An String representing the Totalsupply owned by the passed address.
     */

func TotalSupplyXRC20(token_address string)string {
	client:=ClientURL_()
	tokenAddress := common.HexToAddress(token_address)// token address
	instance, err := NewToken(tokenAddress, client)
	if err != nil {
        
		log.Fatal(err)
	}
	totalSupply, err := instance.TotalSupply(&bind.CallOpts{})
    if err != nil {
        log.Fatal(err)
    }
	var intTotalSupply, _ = new(big.Int).SetString(totalSupply.String(), 10) // convert string to int
	var finalTotalSupply = new(big.Int)
	return (finalTotalSupply.Div(intTotalSupply, DividendData()).String())
	
}

/**
     
     * @param token_address 	The address of the token.
	 * @param owner_address 	The address of the Token's owner.
	 * @param spender_address 	The address of the Spender's address.
     * @return An String representing the Allowance .
     */

func AllowanceXRC20(token_address string , owner_address string , spender_address string)string {
	tokenAddress := common.HexToAddress(token_address)// token address
	ownerAddress := common.HexToAddress(owner_address)
	spenderAddress := common.HexToAddress(spender_address)
	instance, err := NewToken(tokenAddress, ClientURL_())
	if err != nil {
        
		log.Fatal(err)
	}
	allowance, err := instance.Allowance(&bind.CallOpts{},ownerAddress,spenderAddress)
    if err != nil {
        log.Fatal(err)
    }
	return (allowance.String())
	
}

/**
    
     * @param private_key spender's private key.
	 * @param to_address The address to transfer to.
     * @param Value_ The amount to be transferred.
     * @param gasLimit Gas Limit of Contract.
     * @dev Transfer XDC for a specified address
    
     */


func XDCTransferXRC20(private_key string, to_address string, value string,gasLimit uint64  ) string{

	value_in_int := new(big.Int)

	value_in_int1, ok := value_in_int.SetString(value, 10)
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
	
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	toAddress := common.HexToAddress(to_address)
	var data []byte	
	tx := types.NewTransaction(nonce, toAddress, value_in_int1, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	rawTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	rawTxHex := hex.EncodeToString(rawTxBytes)

	client1:=ClientURL_()
    rawTxBytes1, err := hex.DecodeString(rawTxHex)

    tx1 := new(types.Transaction)
    rlp.DecodeBytes(rawTxBytes1, &tx1)

    err = client1.SendTransaction(context.Background(), tx1)
    if err != nil {
		log.Fatal(err)
    }
	return (tx1.Hash().Hex())
}


 /**
     * @dev Transfer token for a specified address
     * @param private_key Sender's private key.
	 * @param token_address The address of the token.

     * @param spenderAddress The address to transfer to.
	 * @param gas_price      Gas price of contract.
     * @param gas_limit      Gas Limit of Contract.
     * @param tokens The amount to be transferred.
     */

func TokenTransferXRC20(private_key string, token_address string, spenderAddress string,gas_price string, gas_limit string,tokens string) string{
	tokenInteger := new(big.Int)
	gasPriceInteger := new(big.Int)
	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	amount, ok := tokenInteger.SetString(tokens, 10)
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
	transferFnSignature := []byte("transfer(address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	//Note- Now we have all the information we need to generate the transaction.
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

	return (signedTx.Hash().Hex()) // tx sent: 0xa56316b637a94c4cc0331c73ef26389d6c097506d581073f927275e7a6ece0bc
}

/**
     * @param private_key 	Owner Private key.
	 * @param token_address 	Token Address.
	 * @param spenderAddress	 The address which will spend the funds.
	 * @param gas_price      Gas price of contract.
     * @param gas_limit      Gas Limit of Contract.
	 * @param Amount           The amount of tokens to be spent.
	 * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
     * Beware that changing an allowance with this method brings the risk that someone may use both the old
     * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
     * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
     */

func ApproveXRC20(private_key string, token_address string,spenderAddress string,gas_price string,gas_limit string,amount string) string{
	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(amount, 10)
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
    transferFnSignature := []byte("approve(address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
    
    paddedAmount := common.LeftPadBytes(amountInteger1.Bytes(), 32)
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

 /**
     * @dev Increase the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * @param private_key     Owner Private key
	 * @param token_address   Token Address for which , allownce need to to increase.
	 * @param spenderAddress	 The address which will spend the funds.
	 * @param gas_price      Gas price of contract.
     * @param gas_limit      Gas Limit of Contract.
     * @param Amount           The amount of tokens to increase the allowance by.
     */

func IncreaseAllowanceXRC20(private_key string, token_address string,spenderAddress string,gas_price string,gas_limit string,amount string)string{

	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(amount, 10)
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

    owner_address := crypto.PubkeyToAddress(*publicKeyECDSA)

    spender_address := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
	allowanceInInteger := new(big.Int)
    allowance, ok := allowanceInInteger.SetString((AllowanceXRC20(token_address,owner_address.String(),spenderAddress)), 10)
    if !ok {
        fmt.Println("SetString: error")
        
    }
	var Result_ = new(big.Int)
	Result_.Add(allowance, amountInteger1)

    nonce, err := client.PendingNonceAt(context.Background(), owner_address)

    value := big.NewInt(0) // in wei (0 
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("approve(address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddress := common.LeftPadBytes(spender_address.Bytes(), 32)

    paddedAmount := common.LeftPadBytes(Result_.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
	var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    //Note- Now we have all the information we need to generate the transaction.



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

 /**
     * @dev Decrease the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To decrement
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * @param private_key     Owner Private key
     * @param token_address   Token Address for which , allownce need to to decrease.

     * @param spenderAddress The address which will spend the funds.
	 * @param gas_price      Gas price of contract.
     * @param gas_limit      Gas Limit of Contract.
     * @param Amount           The amount of tokens to decrease the allowance by.
     */

func DecreaseAllowanceXRC20(private_key string,token_address string,spenderAddress string,gas_price string, gas_limit string, amount string) string{

	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)

	finalGasPrice, ok := gasPriceInteger.SetString(gas_price, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
	gasLimit, _ := strconv.ParseUint(gas_limit, 10, 64)
	
	amountInteger1, ok := amountInteger.SetString(amount, 10)
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

    owner_address := crypto.PubkeyToAddress(*publicKeyECDSA)

    spender_address := common.HexToAddress(spenderAddress)
    tokenAddress := common.HexToAddress(token_address)// token address
	allowanceInInteger := new(big.Int)
    allowance, ok := allowanceInInteger.SetString((AllowanceXRC20(token_address,owner_address.String(),spenderAddress)), 10)
    if !ok {
        fmt.Println("SetString: error")
        
    }
	var Result_ = new(big.Int)
	Result_.Sub(allowance, amountInteger1)

    nonce, err := client.PendingNonceAt(context.Background(), owner_address)
    value := big.NewInt(0) // in wei (0 
    
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("approve(address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddress := common.LeftPadBytes(spender_address.Bytes(), 32)

    paddedAmount := common.LeftPadBytes(Result_.Bytes(), 32)
//This value is the amount of to be transferred for this transaction, which should be 0 since we're transferring XRC-20 Tokens and not ETH. We'll set the value of Tokens to be transferred in the data field later.
//data fied for token
	var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    //Note- Now we have all the information we need to generate the transaction.

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

 /**
     * @dev Transfer tokens from one address to another
	 * @param private_key     Spender's Private key
	 * @param token_address   Token Address
	 * @param from_address 		address The address which you want to send tokens from
     * @param spender_address      address The address which you want to transfer to
	 * @param gas_price      Gas price of contract.
     * @param gas_limit      Gas Limit of Contract.
     * @param Amount           uint256 the amount of tokens to be transferred
     */
func TransferFromMethodXRC20(private_key string, token_address string,from_address string,spender_address string,gas_price string,gas_limit string,amount string)string{
	
	gasPriceInteger := new(big.Int)
	amountInteger := new(big.Int)
	amountInteger1, ok := amountInteger.SetString(amount, 10)
	if !ok {
		fmt.Println("SetString: error")
		
	}
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
    from__address := common.HexToAddress(from_address)
	toAddress := common.HexToAddress(spender_address)
    tokenAddress := common.HexToAddress(token_address)// token address
//Next, we need to form the smart contract function call. The signature of the function we'll be calling is the transfer() function in the XRC-20 specification, and the types of the argument we'll be passing to it. The first argument type is address (the address to which we're sending tokens), and the second argument's type is uint256 (the amount of tokens to send). The result is the string transfer(address,uint256) (no spaces!).
    transferFnSignature := []byte("transferFrom(address,address,uint256)")
//We then need to get the methodID of our function. To do this, we'll import the crypto/sha3 to generate the Keccak256 hash of the function signature. The first 4 bytes of the resulting hash is the methodID:

    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]
//Next we'll zero pad (to the left) the account address we're sending tokens. The resulting byte slice must be 32 bytes long:
    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
    paddedAddressfrom := common.LeftPadBytes(from__address.Bytes(), 32)

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

/**
     
     * @return Private Key of Wallet.
     
*/

func CreateAccount() string{
	privateKey, err := crypto.GenerateKey()
    if err != nil {
        log.Fatal(err)
    }
     privateKeyBytes := crypto.FromECDSA(privateKey)
	return (hexutil.Encode(privateKeyBytes)[2:])
}

 /**
     * @param Privatekey   private key of account.
     * @return A Address of contract.
     * @dev Function to check private key is valid or not.
     */

func CheckAddress(private_key string)  string{
	
	privateKey, err := crypto.HexToECDSA(private_key)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	return(crypto.PubkeyToAddress(*publicKeyECDSA).String())
}
