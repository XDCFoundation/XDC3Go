# XRC-721 Tokens
## XRC721 functions's usage and definations.
 

* OwnerXRC721(tokenAddress string , tokenID string) → common.Address (Returns the owner of the NFT specified by tokenId).
```
//	Owner OFF
OwnerOff__:=XRC721.OwnerXRC721(tokenAddress,Token_ID)
fmt.Println("Owner OFF method : ",OwnerOff__)
```

 

* IsApprovedForAllXRC721(tokenAddress string ,ownerAddress string, operatorAddress string) → bool (Tells whether an operator is approved by a given owner.).
```
//IsApprovedForAll

IsApprovedForAll__:=XRC721.IsApprovedForAllXRC721(tokenAddress,OwnerAddress,OperatorAddress)
fmt.Println("Is approval for all :",IsApprovedForAll__)
```

* NameXRC721(tokenAddress string) → string (Gets the token name.).
```
// Name

Name__:=XRC721.NameXRC721(tokenAddress)
fmt.Println("Name :",Name__)
```
 

* SymbolXRC721(tokenAddress string) → string (Gets the token symbol.).
```
//Symbol

Symbol__:=XRC721.SymbolXRC721(tokenAddress)
fmt.Println("Symbol :", Symbol__)
```
 

* TokenURIXRC721(tokenAddress string, tokenID string) → string (Returns the URI for a given token ID. May return an empty string).
```
//TokenURI

TokenURI__:=XRC721.TokenURIXRC721(tokenAddress,Token_ID)
fmt.Println("Token URI :",TokenURI__)
```

* TokenOfOwnerByIndexXRC721(tokenAddress string, indexNo string, ownerAddress string) → string(Gets the token ID at a given index of the tokens list of the requested owner).
```
//TokenOfOwnerByIndex

TokenOfOwnerByIndex__:=XRC721.TokenOfOwnerByIndexXRC721(tokenAddress,Indexno,OwnerAddress)
fmt.Println("TokenOfOwnerByIndex :",TokenOfOwnerByIndex__)
```
 

* GetApprovedXRC721(tokenAddress string, tokenID string) → common.Address (Gets the approved address for a token ID, or zero if no address set Reverts if the token ID does not exist).
```
 //GetApproved

GetApproved__:=XRC721.GetApprovedXRC721(tokenAddress,Token_ID)
fmt.Println("GetApproved :",GetApproved__)
```

* TotalSupplyXRC721(tokenAddress string) → string (Gets the total amount of tokens stored by the contract).
```
 //TotalSupply

TotalSupply__:=XRC721.TotalSupplyXRC721(tokenAddress)
fmt.Println("TotalSupply :",TotalSupply__)
```

* BalanceXRC721(tokenAddress string , ownerAddress string) → string (Returns the number of NFTs in owner's account).
```
//BalanceOff

BalanceOff__:=XRC721.BalanceXRC721(tokenAddress,OwnerAddress)
fmt.Println("BalanceOff :",BalanceOff__)
```
 

* SupportInterfaceXRC721(tokenAddress string, interfaceID int) → bool (Return True or False).
```
//SupportInterface

SupportInterface__:=XRC721.SupportInterfaceXRC721(tokenAddress,Interface_id)
fmt.Println("SupportInterface_ :",SupportInterface__)
```

 

* ApproveXRC721(private_key string , token_address string,spenderAddress string,gas_price string,gas_limit string,tokenID string ) -> string (Approves another address to transfer the given token ID The zero address indicates there is no approved address. There can only be one approved address per token at a given time. Can only be called by the token owner or an approved operator.)
```
// Approve 

Approve__:=XRC721.ApproveXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("Approve_ :",Approve__)
```
 

* SafeTransferXRC721(private_key string,token_address string ,spenderAddress string ,gas_price string ,gas_limit string , tokenID string) -> string (Use for safely transfer token’s ownership).
```
 //SafeTransfer

SafeTransfer__:=XRC721.SafeTransferXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("SafeTransfer_: ",SafeTransfer__)
```

* TransferFromXRC721(private_key string ,token_address string ,spenderAddress string, gas_price string,gas_limit string ,tokenID string) -> string (Transfers the ownership of a given token ID to another address. Usage of this method is discouraged, use safeTransferFrom whenever possible. Requires the msg.sender to be the owner, approved, or operator).
```
//TransferFrom

TransferFrom__:=XRC721.TransferFromXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("TransferFrom_ :",TransferFrom__)
```
 

* SetapprovalforallXRC721(private_key string,token_address string,spenderAddress string,gas_price string,gas_limit string,boolValue string) -> string (Sets or unsets the approval of a given operator An operator is allowed to transfer all tokens of the sender on their behalf).
```
//setapproovalforall

Setapprovalforall__:=XRC721.SetapprovalforallXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Set_approval)
fmt.Println("setappforall__",Setapprovalforall__)
```
### NOTE - boolvalue pass in only 0 or 1.

0- False

1-True


 

## How to call Functions In Go SDK with examples.

### Use Like this in your main package.
```
package main
import (
	"fmt"
	"github.com/XDCFoundation/XDC3Go/XRC721"
)
func main(){
	tokenAddress := ""
	Token_ID:= "21"
	OwnerAddress:= ""
	OperatorAddress:= ""
	Indexno:= "0"
	var Interface_id int 
	Interface_id=0x80ac58cd
	
//	Owner OFF

OwnerOff__:=XRC721.OwnerXRC721(tokenAddress,Token_ID)
fmt.Println("Owner OFF method : ",OwnerOff__)

//IsApprovedForAll

IsApprovedForAll__:=XRC721.IsApprovedForAllXRC721(tokenAddress,OwnerAddress,OperatorAddress)
fmt.Println("Is approval for all :",IsApprovedForAll__)

// Name

Name__:=XRC721.NameXRC721(tokenAddress)
fmt.Println("Name :",Name__)

//Symbol

Symbol__:=XRC721.SymbolXRC721(tokenAddress)
fmt.Println("Symbol :", Symbol__)

//TokenURI

TokenURI__:=XRC721.TokenURIXRC721(tokenAddress,Token_ID)
fmt.Println("Token URI :",TokenURI__)

//TokenOfOwnerByIndex

TokenOfOwnerByIndex__:=XRC721.TokenOfOwnerByIndexXRC721(tokenAddress,Indexno,OwnerAddress)
fmt.Println("TokenOfOwnerByIndex :",TokenOfOwnerByIndex__)

//GetApproved

GetApproved__:=XRC721.GetApprovedXRC721(tokenAddress,Token_ID)
fmt.Println("GetApproved :",GetApproved__)

//TotalSupply

TotalSupply__:=XRC721.TotalSupplyXRC721(tokenAddress)
fmt.Println("TotalSupply :",TotalSupply__)

//BalanceOff

BalanceOff__:=XRC721.BalanceXRC721(tokenAddress,OwnerAddress)
fmt.Println("BalanceOff :",BalanceOff__)

//SupportInterface

SupportInterface__:=XRC721.SupportInterfaceXRC721(tokenAddress,Interface_id)
fmt.Println("SupportInterface_ :",SupportInterface__)

//---------------------------------------------------------------------------------

// Write Methods

Private_key:=""
Spender_address_for_Write_op:=""
Token_address_for_write_op:=""
Token_id_for_write_op:="21"
Gas_Limit:="3000000"
Gas_Price:="3500000"
Set_approval:="0"

// Approve 

Approve__:=XRC721.ApproveXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("Approve_ :",Approve__)

//SafeTransfer

SafeTransfer__:=XRC721.SafeTransferXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("SafeTransfer_: ",SafeTransfer__)

//TransferFrom

TransferFrom__:=XRC721.TransferFromXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Token_id_for_write_op)
fmt.Println("TransferFrom_ :",TransferFrom__)

//setapproovalforall

Setapprovalforall__:=XRC721.SetapprovalforallXRC721(Private_key,Token_address_for_write_op,Spender_address_for_Write_op,Gas_Price,Gas_Limit,Set_approval)
fmt.Println("setappforall__",Setapprovalforall__)

}
```
