package authservice

import (
	"context"
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
	case "map-user", "unmap", "transfer-ownership", "set-role":
		fmt.Fprintf(os.Stderr, "SECURITY ERROR: CLI-based data mutation via exec pod is DISABLED for security hardening.\n")
		fmt.Fprintf(os.Stderr, "All account modifications and workflow transfers must be performed through the authenticated REST API:\n")
		fmt.Fprintf(os.Stderr, "  POST /admin/api/v1/transfer-ownership\n")
		fmt.Fprintf(os.Stderr, "  POST /admin/api/v1/users/{email}/role\n")
		fmt.Fprintf(os.Stderr, "Header required: Authorization: Bearer <ADMIN_API_TOKEN>\n")
		os.Exit(1)
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

	case "list-users":
		users, err := db.ListUsers(ctx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "ID\tEMAIL\tROLE\tDISABLED\tPROJECT ID\tCREATED AT")
		for _, u := range users {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\t%s\n",
				u.ID, u.Email, u.Role, u.Disabled, u.PersonalProjectID, u.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		_ = w.Flush()
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
	fmt.Println("n8n-auth-service CLI Management Tool (Read-Only Mode)")
	fmt.Println()
	fmt.Println("Security Policy:")
	fmt.Println("  All mutating commands (map-user, transfer-ownership, set-role) via exec pod are DISABLED.")
	fmt.Println("  Use the authenticated REST API with Bearer Token (/admin/api/v1/...) for all mutations.")
	fmt.Println()
	fmt.Println("Read-Only Commands:")
	fmt.Println("  list-users     Display all n8n users and their current roles")
	fmt.Println("  list-mappings  Display all active account mappings")
	fmt.Println("  healthcheck    Run HTTP health check probe")
	fmt.Println()
}
