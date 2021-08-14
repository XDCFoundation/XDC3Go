package XRC721
import(
	"github.com/XDCFoundation/XDC3Go/ethclient"
	"encoding/binary"
	"log"
)
// fetching client
func ClientURL_()*ethclient.Client{
    client, err := ethclient.Dial("http://rpc.apothem.network/")
    if err != nil {
        log.Fatal(err)
    }
    return client
}
// for int to bytes array
func toByteArray(i int) (arr [4]byte) {
    binary.BigEndian.PutUint32(arr[0:4], uint32(i))
    return
}

