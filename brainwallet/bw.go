package main

import(
    "os"
    "bufio"
    "fmt"
    "github.com/conformal/btcec"
    "github.com/conformal/btcutil"
    "github.com/conformal/btcwire"
    "github.com/conformal/fastsha256"
)


func main() {
    lines := bufio.NewReader(os.Stdin)
    hasher := fastsha256.New()
    for {
        line, _, err := lines.ReadLine()
        if err != nil { break }
    
        hasher.Reset()
        hasher.Write(line)
        sum := hasher.Sum(nil)

        _, pub := btcec.PrivKeyFromBytes(btcec.S256(), sum)
        var apk, _ = btcutil.NewAddressPubKey(pub.SerializeUncompressed(), btcwire.MainNet)
        fmt.Println(apk.EncodeAddress())
        apk, _ = btcutil.NewAddressPubKey(pub.SerializeCompressed(), btcwire.MainNet)
        fmt.Println(apk.EncodeAddress())
    }
}
