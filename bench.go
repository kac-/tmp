package main
import (
	"fmt"
	"flag"
	"time"
)

var iterations int64
var sleepLength int

func init(){
	flag.Int64Var(&iterations, "l", 0, "loop iterations")
	flag.IntVar(&sleepLength, "s",0, "sleep length")
}

func main() {
	flag.Parse()
	fmt.Printf("%d %d\n", iterations, sleepLength)
	
	args := flag.Args()
	for _,i := range args {
		fmt.Printf("flag %s\n", i);
	}
	sleep := time.Duration(sleepLength) * time.Millisecond
	for {
		start := time.Now()
		for i := int64(0); i < iterations; i++ {
		}
		elapsed := time.Since(start)
		fmt.Println(elapsed)
		time.Sleep(sleep)
	}
	
}
