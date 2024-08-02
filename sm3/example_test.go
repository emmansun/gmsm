package sm3_test

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/emmansun/gmsm/sm3"
)

func ExampleSum() {
	sum := sm3.Sum([]byte("hello world\n"))
	fmt.Printf("%x", sum)
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

func ExampleNew() {
	h := sm3.New()
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

func ExampleNew_file() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sm3.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x", h.Sum(nil))
}
