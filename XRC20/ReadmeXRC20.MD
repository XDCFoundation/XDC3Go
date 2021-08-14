# XRC20 Token
## XRC20 functions's usage and definations.
 

* CreateAccount() → string (Returns the Private Key).
```
	//for account creation
	CreateAccount1:=XRC20.CreateAccount()
	fmt.Println("CreateAccount Private key :",CreateAccount1)
```

 

* CheckAddress(private_key string) → string (Returns the Address User).
```
	// for check address
	CheckAddress1:=XRC20.CheckAddress(CreateAccount1)
	fmt.Println("User Address :",CheckAddress1)
```
 

* NameXRC20(token_address string) → string (Returns the name of the token).
```
	//for Name
	Name1:=XRC20.NameXRC20(Token_address)
	fmt.Println("name :",Name1)
```

* SymbolXRC20(token_address string) → string (Returns the symbol of the token, usually a shorter version of the name).
```
	// for Symbol
	Symbol1:=XRC20.SymbolXRC20(Token_address)
	fmt.Println("symbol: ",Symbol1)
```
 

* DecimalsXRC20(token_address string) → uint8 (Returns the number of decimals used to get its user representation. For example, if decimals equals 2, a balance of 505 tokens should be displayed to a user as 5,05 (505 / 10 ** 2)).Tokens usually opt for a value of 18, imitating the relationship between Ether and Wei.
```
	// for decimal
	Decimals1:=XRC20.DecimalsXRC20(Token_address)
	fmt.Println("Decimals: ",Decimals1)
```
 

* TotalSupplyXRC20(token_address string) → string(Returns the number of tokens in existence).
```
	// for totalsupply
	Total_supply1:=XRC20.TotalSupplyXRC20(Token_address)
	fmt.Println("Total_supply: ",Total_supply1)
```
 

* BalanceXRC20(token_address string ,owner_address string) → string (Returns the number of tokens owned by the account).
```
	// for Balanceoff
	BalanceOf1:=XRC20.BalanceXRC20(Token_address,Owner_address)
	fmt.Println("BalanceOf: ",BalanceOf1)
```

* AllowanceXRC20(token_address string , owner_address string , spender_address string) → string (Returns the remaining number of tokens that the spender will be allowed to spend on behalf of the owner through transferFrom. This is zero by default).
```
	//for Allowance
	Allowance1:=XRC20.AllowanceXRC20(Token_address,Owner_address,Spender_address)
	fmt.Println("Allowance: ",Allowance1)
```

* ApproveXRC20(private_key string, token_address string,spenderAddress string,gas_price string,gas_limit string,amount string) -> string (Pass Private key , Token address , Spender address , Gas Price, Gas Limit . It will return a transaction hash).
```
 	// for Approve
	Approve_1:=XRC20.ApproveXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"3")
	fmt.Println("Approve_: ",Approve_1)
```

* XDCTransferXRC20(private_key string, to_address string, value string,gasLimit uint64  ) -> string (Moves amount XDC from the caller’s account to recipient. It will return a transaction hash).
```
 	// for XDC Transfer
	XDCTransfer1:=XRC20.XDCTransferXRC20(Private_key,Spender_address,"1",Gaslimit_In_Uint)
	fmt.Println("XDCTransfer: ",XDCTransfer1)
```

* TokenTransferXRC20(private_key string, token_address string, spenderAddress string,gas_price string, gas_limit string,tokens string) -> string (Moves tokens from the caller’s account to recipient. It will return a transaction hash).
```
	// for Token Transfer
	TokenTransfer_1:=XRC20.TokenTransferXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"5")
	fmt.Println("TokenTransfer_: ",TokenTransfer_1)
```
 

* TransferFromMethodXRC20(private_key string, token_address string,from_address string,spender_address string,gas_price string,gas_limit string,amount string) -> string (Pass Private key , Token address ,from_address, Spender address , Gas Price, Gas Limit and Amount . It will return a transaction hash).
## Note- Senaorio and usage of FromTransfer method-
    
### Scenario 1


* Adderess 1 : 100 Spender
* Adderess 2 : 0 Delegate
* Adderess 3: 0 Receiver
* Adderess 4: 0 Receiver
* Adderess 3: 0 Receiver
* Adderess 4: 0 Receiver


### Spender Approve a account to delegate the tokens to receiver account


* Adderess 1 — Approve(Adderess 2 , 100)


* Adderess 2 — transferfrom(Adderess 1 , Adderess 3, 25); — Yes
* Adderess 2 — transferfrom(Adderess 1 , Adderess 4, 25); — Yes
* Adderess 2 — transferfrom(Adderess 1 , Adderess 3, 25); — Yes
* Adderess 2 — transferfrom(Adderess 1 , Adderess 4, 25); — Yes
* Adderess 2 — transferfrom(Adderess 1 , Adderess 3, 25); — Fail
```
	// for  TransferFrom
	FromTransfer_1:=XRC20.TransferFromMethodXRC20(Private_key,Token_address,"0xd23e72405951a6aff30f222aa23fdba83bb0a391",Spender_address,Gas_Price,Gas_limit,"3000000000000000000")
	fmt.Println("FromTransfer_: ",FromTransfer_1)
```





 

* IncreaseAllowanceXRC20(private_key string, token_address string,spenderAddress string,gas_price string,gas_limit string,amount string) -> string (Automatically  increases the allowance granted to spender by the caller).
```
 	// for Increase Allowance
	IncreaseAllowance_1:=XRC20.IncreaseAllowanceXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"1")
	fmt.Println("IncreaseAllowance_1: ",IncreaseAllowance_1)
```

* DecreaseAllowanceXRC20(private_key string,token_address string,spenderAddress string,gas_price string, gas_limit string, amount string) -> string (Automatically  decreases the allowance granted to spender by the caller).
```

	// for Decrease Allowance
	DecreaseAllowance_1:=XRC20.DecreaseAllowanceXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"1")
	fmt.Println("DecreaseAllowance_: ",DecreaseAllowance_1)
```
 

## How to call Functions In Go SDK with examples.

 

* Use Like this in your main package.

```
package main
import(
	"github.com/XDCFoundation/XDC3Go/XRC20"
	"fmt"
)
func main(){
	Private_key := ""
	Token_address := ""
	Owner_address := ""
	Spender_address := ""
	fromAddressForTransferFromMethod := ""
	Gas_limit :="3000000"
	Gas_Price := "3500000"
	var Gaslimit_In_Uint uint64
	Gaslimit_In_Uint=3000000
	Tokens_:= "3000000000000000000" //It mean 3 tokens
	XDC_transfer_data:= "3000000000000000000"  // IT mean 3 XDC

	//for account creation
	CreateAccount1:=XRC20.CreateAccount()
	fmt.Println("CreateAccount Private key :",CreateAccount1)

	// for check address
	CheckAddress1:=XRC20.CheckAddress(CreateAccount1)
	fmt.Println("User Address :",CheckAddress1)
	
	//for Name
	Name1:=XRC20.NameXRC20(Token_address)
	fmt.Println("name :",Name1)
	
	// for Symbol
	Symbol1:=XRC20.SymbolXRC20(Token_address)
	fmt.Println("symbol: ",Symbol1)
	
	// for decimal
	Decimals1:=XRC20.DecimalsXRC20(Token_address)
	fmt.Println("Decimals: ",Decimals1)
	
	// for totalsupply
	Total_supply1:=XRC20.TotalSupplyXRC20(Token_address)
	fmt.Println("Total_supply: ",Total_supply1)
	
	// for Balanceoff
	BalanceOf1:=XRC20.BalanceXRC20(Token_address,Owner_address)
	fmt.Println("BalanceOf: ",BalanceOf1)
	
	//for Allowance
	Allowance1:=XRC20.AllowanceXRC20(Token_address,Owner_address,Spender_address)
	fmt.Println("Allowance: ",Allowance1)
	
	// for Approve
	Approve_1:=XRC20.ApproveXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"3")
	fmt.Println("Approve_: ",Approve_1)
	
	// // for XDC Transfer
	XDCTransfer1:=XRC20.XDCTransferXRC20(Private_key,Spender_address,XDC_transfer_data,Gaslimit_In_Uint)
	fmt.Println("XDCTransfer: ",XDCTransfer1)
	
	// for Token Transfer
	TokenTransfer_1:=XRC20.TokenTransferXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"5")
	fmt.Println("TokenTransfer_: ",TokenTransfer_1)
	
	// for  TransferFrom
	FromTransfer_1:=XRC20.TransferFromMethodXRC20(Private_key,Token_address,fromAddressForTransferFromMethod,Spender_address,Gas_Price,Gas_limit,Tokens_)
	fmt.Println("FromTransfer_: ",FromTransfer_1)
	
	// for Increase Allowance
	IncreaseAllowance_1:=XRC20.IncreaseAllowanceXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"1")
	fmt.Println("IncreaseAllowance_1: ",IncreaseAllowance_1)
	
	// for Decrease Allowance
	DecreaseAllowance_1:=XRC20.DecreaseAllowanceXRC20(Private_key,Token_address,Spender_address,Gas_Price,Gas_limit,"1")
	fmt.Println("DecreaseAllowance_: ",DecreaseAllowance_1)
	
}
```