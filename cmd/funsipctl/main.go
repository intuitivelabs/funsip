package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/funsip/funsip/pkg/auth"
	"github.com/funsip/funsip/pkg/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "subscriber", "sub":
		handleSubscriber()
	case "location", "loc":
		handleLocation()
	case "status":
		handleHTTP("/status")
	case "stats":
		handleHTTP("/stats")
	case "transactions", "tx":
		handleHTTP("/transactions")
	case "registrations", "reg":
		handleHTTP("/registrations")
	case "logs":
		handleHTTP("/logs")
	case "reload":
		handleReload()
	case "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`funsipctl - FunSIP management CLI

Usage: funsipctl <command> [options]

Database commands (use -db flag for database path, default: funsip.db):
  subscriber list [domain]          List subscribers
  subscriber add <user> <domain> <password>  Add subscriber
  subscriber delete <user> <domain> Delete subscriber
  location list                     List all registrations
  location delete <aor>             Delete registrations for AOR
  location purge                    Purge expired registrations

Server commands (use -api flag for API URL, default: http://127.0.0.1:8080):
  status                           Show server status
  stats                            Show server statistics
  transactions                     Show active transactions
  registrations                    Show active registrations
  logs                             Show recent log messages
  reload                           Hot-reload routing script`)
}

func getDBPath() string {
	for i, arg := range os.Args {
		if arg == "-db" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return "funsip.db"
}

func getAPIURL() string {
	for i, arg := range os.Args {
		if arg == "-api" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return "http://127.0.0.1:8080"
}

func filterArgs() []string {
	var args []string
	skip := false
	for _, arg := range os.Args[2:] {
		if skip {
			skip = false
			continue
		}
		if arg == "-db" || arg == "-api" {
			skip = true
			continue
		}
		args = append(args, arg)
	}
	return args
}

func handleSubscriber() {
	args := filterArgs()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "subscriber: missing subcommand (list|add|delete)")
		os.Exit(1)
	}

	db, err := store.Open(getDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	switch args[0] {
	case "list":
		domain := ""
		if len(args) > 1 {
			domain = args[1]
		}
		subs, err := db.ListSubscribers(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USERNAME\tDOMAIN\tHA1")
		for _, s := range subs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", s.Username, s.Domain, s.HA1)
		}
		w.Flush()

	case "add":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: subscriber add <username> <domain> <password>")
			os.Exit(1)
		}
		username, domain, password := args[1], args[2], args[3]
		ha1 := auth.ComputeHA1(username, domain, password)
		sub := &store.Subscriber{
			Username: username,
			Domain:   domain,
			HA1:      ha1,
			Password: password,
		}
		if err := db.UpsertSubscriber(sub); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("subscriber %s@%s added (HA1: %s)\n", username, domain, ha1)

	case "delete":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: subscriber delete <username> <domain>")
			os.Exit(1)
		}
		if err := db.DeleteSubscriber(args[1], args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("subscriber %s@%s deleted\n", args[1], args[2])

	default:
		fmt.Fprintf(os.Stderr, "subscriber: unknown subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleLocation() {
	args := filterArgs()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "location: missing subcommand (list|delete|purge)")
		os.Exit(1)
	}

	db, err := store.Open(getDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	switch args[0] {
	case "list":
		bindings, err := db.ListAllBindings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "AOR\tCONTACT\tRECEIVED\tTRANSPORT\tEXPIRES")
		for _, b := range bindings {
			fmt.Fprintf(w, "%s\t%s\t%s:%d\t%s\t%s\n",
				b.AOR, b.Contact,
				b.ReceivedIP, b.ReceivedPort,
				b.Transport,
				b.ExpiresAt.Format("15:04:05"))
		}
		w.Flush()

	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: location delete <aor>")
			os.Exit(1)
		}
		if err := db.DeleteAllBindings(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("bindings for %s deleted\n", args[1])

	case "purge":
		n, err := db.PurgeExpired()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("purged %d expired bindings\n", n)

	default:
		fmt.Fprintf(os.Stderr, "location: unknown subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleHTTP(path string) {
	url := getAPIURL() + path
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var pretty interface{}
	if json.Unmarshal(body, &pretty) == nil {
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println(string(body))
	}
}

func handleReload() {
	url := getAPIURL() + "/reload"
	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if json.Unmarshal(body, &result) == nil {
		if result["success"] == true {
			fmt.Println("Script reloaded successfully")
		} else {
			fmt.Fprintf(os.Stderr, "Reload failed: %v\n", result["error"])
			os.Exit(1)
		}
	}
}
