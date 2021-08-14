package XRC20
import(
	"math/big"
	"github.com/XDCFoundation/XDC3Go/ethclient"
	"log"

)
func DividendData() *big.Int{
	dividends  := big.NewInt(1000000000000000000)
	return dividends
} 
// fetching client
func ClientURL_()*ethclient.Client{
    client, err := ethclient.Dial("http://rpc.apothem.network/")
    if err != nil {
        log.Fatal(err)
    }
    return client
}
