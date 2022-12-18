package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	headOnly := flag.Bool("headOnly", false, "only show header and quit")
	keyFile := flag.String("keyFile", "", "key file")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [OPTIONS] kdb\n\nOPTIONS:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("missing kdb file")
	}

	if fp, ferr := os.Open(flag.Arg(0)); ferr != nil {
		log.Fatalf("kdb %s: %v\n", flag.Arg(0), ferr)
	} else {
		defer fp.Close()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sig
			fp.Close()
			os.Exit(1)
		}()

		proc(fp, *headOnly, *keyFile)
	}
}

func proc(fp *os.File, headOnly bool, keyFile string) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered", r)
		}
	}()

	if hdr, herr := getHead(fp); herr != nil {
		log.Println(herr)
	} else if headOnly {
		log.Printf("%+v\n", hdr)
	} else {
		if err := interact(hdr, fp, keyFile); err != nil {
			log.Println(err)
		}
	}
}

func interact(hdr *header, fp *os.File, keyFile string) error {
	body, berr := decBody(hdr, fp, keyFile)
	if berr != nil {
		return berr
	}

	XMLReader, xerr := bodyToXMLReader(body, hdr.compressed)
	if xerr != nil {
		return xerr
	}

	if list, err := XMLToList(XMLReader, NewSalsaStream(hdr.keySalsa)); err != nil {
		return err
	} else {
		mainloop(list)
	}
	return nil
}
