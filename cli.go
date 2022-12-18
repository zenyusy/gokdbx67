package main

import (
	"fmt"
	"strings"
)

const (
	miPhase3      = 1
	miPhaseNeedle = 2

	ynYes = 11
	ynNo  = 12
)

var running = true

func mustInput(p string, phase int) string {
	r := ""
	for {
		fmt.Printf("%s? ", p)
		n, err := fmt.Scanln(&r)
		if err != nil || n != 1 {
			fmt.Println("Must Input")
			continue
		}
		switch phase {
		case miPhase3:
			switch r[0] {
			case 's', 'S':
				return "s"
			case 'l', 'L':
				return "l"
			case 'e', 'E':
				return "e"
			}
		case miPhaseNeedle:
			if trimmed := strings.TrimSpace(r); len(trimmed) != 0 {
				return strings.ToLower(trimmed)
			}
		}
	}
}

func mainloop(list []listItem) {
	for {
		input := mustInput("Search List Exit", miPhase3)
		switch input {
		case "e":
			return
		case "l":
			pageList(list)
		case "s":
			fzSearch(list)
		}
	}
}

func yesNo(q string, lazy int) int {
	if lazy == ynYes {
		fmt.Printf("%s ? [y]/n ", q)
	} else {
		fmt.Printf("%s ? y/[n] ", q)
	}
	r := ""
	n, err := fmt.Scanln(&r)
	if err != nil || n != 1 {
		return lazy
	}
	switch r[0] {
	case 'y', 'Y':
		return ynYes
	case 'n', 'N':
		return ynNo
	default:
		return lazy
	}
}

func pageList(li []listItem) {
	for idx, item := range li {
		fmt.Printf("\n#%4d ", idx)
		item.show("; ")
		if idx%10 == 9 {
			if yesNo("more", ynYes) == ynNo {
				return
			}
		}
	}
	fmt.Println("list exhausted")
}

func fzSearch(li []listItem) {
	needle := mustInput("keyword", miPhaseNeedle)
	for _, item := range li {
		if item.match(needle) {
			item.show("\n")
			if yesNo("that's it", ynNo) == ynYes {
				item.serve()
				return
			}
		}
	}
	fmt.Println("no match for ", needle)
}
