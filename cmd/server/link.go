package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Busness-app/kypassword-server/internal/users"
)

// Migration subcommands. They exist because the operator cannot sign in to fix an
// unlinked account: KySignOn is the only way in, and the server refuses to start until
// every active account has a KySignOn identity. So these work with no session, no
// network and no SSO configured — they edit users.json and nothing else.
const migrationUsage = `KyPassword migration commands:

  kypassword-server link-sso --username <name> --sub <kysignon-user-id>
        Bind a local account to its KySignOn identity.

  kypassword-server deactivate --username <name>
        Retire an account that has no KySignOn identity. Its vault is kept.

The KySignOn user ID is the value shown in the KySignOn admin user list, and is the
same value KySignOn puts in the OIDC 'sub' claim.
`

// runMigrationCommand dispatches a subcommand. It reports whether one was recognised, so
// main can fall through to starting the server when the first argument is not a command.
func runMigrationCommand(args []string, out io.Writer) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "link-sso":
		return true, runLinkSSO(configDirFromEnv(), args[1:], out)
	case "deactivate":
		return true, runDeactivate(configDirFromEnv(), args[1:], out)
	case "help", "-h", "--help":
		fmt.Fprint(out, migrationUsage)
		return true, nil
	}
	return false, nil
}

func runLinkSSO(configDir string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("link-sso", flag.ContinueOnError)
	fs.SetOutput(out)
	username := fs.String("username", "", "the local KyPassword account to link")
	sub := fs.String("sub", "", "the KySignOn user ID, which is the OIDC subject")
	email := fs.String("email", "", "optional: the account's address in KySignOn")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *sub == "" {
		return errors.New("link-sso requires --username and --sub")
	}

	store, err := users.NewStore(configDir)
	if err != nil {
		return fmt.Errorf("open %s/users.json: %w", configDir, err)
	}

	u, err := store.GetByUsername(*username)
	if err != nil {
		return fmt.Errorf("no account named %q in %s/users.json", *username, configDir)
	}

	// LinkSSO refuses a subject already bound elsewhere. Report it plainly: two accounts
	// sharing one KySignOn identity is the duplication this migration exists to prevent.
	if existing, errSub := store.GetBySSOSub(*sub); errSub == nil && existing.ID != u.ID {
		return fmt.Errorf("subject %q is already linked to account %q; unlink or deactivate that account first", *sub, existing.Username)
	}

	if err := store.LinkSSO(u.ID, *sub, u.Username, *email); err != nil {
		return fmt.Errorf("link %q: %w", *username, err)
	}

	fmt.Fprintf(out, "Linked %s (id %s) to KySignOn subject %s.\n", u.Username, u.ID, *sub)
	return nil
}

func runDeactivate(configDir string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("deactivate", flag.ContinueOnError)
	fs.SetOutput(out)
	username := fs.String("username", "", "the local KyPassword account to retire")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("deactivate requires --username")
	}

	store, err := users.NewStore(configDir)
	if err != nil {
		return fmt.Errorf("open %s/users.json: %w", configDir, err)
	}

	u, err := store.GetByUsername(*username)
	if err != nil {
		return fmt.Errorf("no account named %q in %s/users.json", *username, configDir)
	}
	if !u.Active {
		fmt.Fprintf(out, "%s (id %s) is already inactive; nothing to do.\n", u.Username, u.ID)
		return nil
	}

	if err := store.Deactivate(u.ID); err != nil {
		return fmt.Errorf("deactivate %q: %w", *username, err)
	}

	// Deactivation is not deletion. The vault stays on disk, and stays downloadable if
	// the account is ever reactivated.
	fmt.Fprintf(out, "Deactivated %s (id %s). Its vault is retained.\n", u.Username, u.ID)
	return nil
}

func configDirFromEnv() string {
	if dir := os.Getenv("CONFIG_DIR"); dir != "" {
		return dir
	}
	return "./config"
}
