package authservice

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// RunCLI handles CLI subcommands executed directly inside the container.
func RunCLI(ctx context.Context, args []string, cfg *Config, db *DB) bool {
	if len(args) < 2 {
		return false
	}

	cmd := args[1]
	switch cmd {
	case "map-user":
		fs := flag.NewFlagSet("map-user", flag.ExitOnError)
		oidc := fs.String("oidc", "", "OIDC user email (e.g. lab-test3@lab.local)")
		replace := fs.String("replace", "", "Legacy local n8n email to replace (e.g. developer-loan@lab.local)")
		first := fs.String("first", "User", "First name for OIDC account")
		last := fs.String("last", "Lab", "Last name for OIDC account")
		_ = fs.Parse(args[2:])

		if *oidc == "" || *replace == "" {
			fmt.Println("Error: both --oidc and --replace flags are required.")
			fmt.Println("Usage: n8n-auth-service map-user --oidc <oidc-email> --replace <local-email>")
			os.Exit(1)
		}

		fmt.Printf("Mapping OIDC user %q to take over local account %q...\n", *oidc, *replace)
		if err := db.ExecuteTakeover(ctx, *oidc, *replace, *first, *last); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("SUCCESS: Account %q has taken over all workflows, credentials, and settings of %q!\n", *oidc, *replace)
		return true

	case "list-mappings":
		list, err := db.ListMappings(ctx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("No active account mappings found.")
			return true
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "OIDC EMAIL\tTARGET N8N EMAIL\tORIGINAL LOCAL\tSTATUS\tCREATED AT")
		for _, m := range list {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				m.OIDCEmail, m.TargetN8nEmail, m.OriginalLocalEmail, m.Status, m.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		_ = w.Flush()
		return true

	case "unmap":
		fs := flag.NewFlagSet("unmap", flag.ExitOnError)
		oidc := fs.String("oidc", "", "OIDC user email to remove from mapping")
		_ = fs.Parse(args[2:])

		if *oidc == "" {
			fmt.Println("Error: --oidc flag is required.")
			os.Exit(1)
		}

		if err := db.DeleteMapping(ctx, *oidc); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SUCCESS: Mapping for %q removed.\n", *oidc)
		return true

	case "help", "--help", "-h":
		printHelp()
		return true

	default:
		// Not a CLI command, proceed to daemon mode
		return false
	}
}

func printHelp() {
	fmt.Println("n8n-auth-service CLI Management Tool")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  map-user       Map an OIDC account to take over an existing local n8n account")
	fmt.Println("                 Flags: --oidc <email> --replace <localEmail> [--first <name>] [--last <name>]")
	fmt.Println("  list-mappings  Display all active account mappings")
	fmt.Println("  unmap          Remove an account mapping")
	fmt.Println("                 Flags: --oidc <email>")
	fmt.Println("  healthcheck    Run HTTP health check probe")
	fmt.Println()
}
