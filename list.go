package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
)

func pushClip(w []byte) {
	cmd := exec.Command("xclip", "-sel", "c")
	if len(w) == 0 {
		cmd.Stdin = nil
	} else {
		cmd.Stdin = bytes.NewReader(w)
	}
	if err := cmd.Run(); err != nil {
		log.Println("push clipboard:", err)
	}
}

type listItem struct {
	kv map[string]string
	p  []byte
}

func (li *listItem) show(delim string) {
	for k, v := range li.kv {
		if len(v) != 0 {
			fmt.Printf("%s : %s%s", k, v, delim)
		}
	}
	fmt.Println("")
}

func (li *listItem) match(needle string) bool {
	// lowercase
	for _, attrib := range []string{"Notes", "Title", "URL", "UserName"} {
		if val := li.kv[attrib]; len(val) != 0 {
			if strings.Index(strings.ToLower(val), needle) != -1 {
				return true
			}
		}
	}
	return false
}

func (li *listItem) serve() {
	if len(li.p) != 0 && yesNo("psw clip", ynYes) == ynYes {
		pushClip(li.p)
	}
	if un := li.kv["UserName"]; len(un) != 0 && yesNo("name clip", ynYes) == ynYes {
		pushClip([]byte(un))
	}
	if yesNo("CLEAR clip", ynYes) == ynYes {
		pushClip(nil)
	}
}

func XMLToList(XMLReader io.Reader, s *SalsaStream) ([]listItem, error) {
	groups, gerr := readerToGroup(XMLReader)
	if gerr != nil {
		return nil, gerr
	}
	ret := make([]listItem, 0, 300)
	err := groupToList(groups, &ret, s)
	return ret, err
}

func groupToList(groups []Group, out *[]listItem, s *SalsaStream) error {
	for _, groupItem := range groups {
		for _, entry := range groupItem.Entries {
			li := listItem{kv: make(map[string]string)}

			for _, curKV := range entry.Values {
				if curKV.Value.Protected == "True" {
					t, err := s.Unpack(curKV.Value.Content)
					if err != nil {
						return fmt.Errorf("salsa decrypt: %v", err)
					}
					if li.p == nil && curKV.Key == "Password" {
						li.p = t
					}
				} else if curKV.Key != "Password" {
					li.kv[curKV.Key] = curKV.Value.Content
				}
			}

			for _, hist := range entry.Histories {
				for _, entry := range hist.Entries {
					for _, histKV := range entry.Values {
						if histKV.Value.Protected == "True" {
							_, herr := s.Unpack(histKV.Value.Content)
							if herr != nil {
								return fmt.Errorf("salsa decrypt hist: %v", herr)
							}
						}
					}
				}
			}
			*out = append(*out, li)
		}
		if len(groupItem.Groups) != 0 {
			if rerr := groupToList(groupItem.Groups, out, s); rerr != nil {
				return rerr
			}
		}
	}
	return nil
}
