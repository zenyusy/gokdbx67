package main

import (
	"encoding/xml"
	"fmt"
	"io"
)

type V struct {
	Content   string `xml:",chardata"`
	Protected string `xml:"Protected,attr,omitempty"`
}

type ValueData struct {
	Key   string `xml:"Key"`
	Value V      `xml:"Value"`
}

type History struct {
	Entries []Entry `xml:"Entry"`
}

type Entry struct {
	Values    []ValueData `xml:"String,omitempty"`
	Histories []History   `xml:"History"`
}

type Group struct {
	Entries []Entry `xml:"Entry,omitempty"`
	Groups  []Group `xml:"Group,omitempty"`
}

type RootData struct {
	Groups []Group `xml:"Group"`
}

type XObj struct {
	XMLName xml.Name  `xml:"KeePassFile"`
	Root    *RootData `xml:"Root"`
}

func readerToGroup(XMLReader io.Reader) ([]Group, error) {
	XML := &XObj{}
	if err := xml.NewDecoder(XMLReader).Decode(XML); err != nil {
		return nil, fmt.Errorf("XML parse: %v", err)
	}
	return XML.Root.Groups, nil
}
