package authservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// MappingRecord represents a mapping between an OIDC account and an n8n account.
type MappingRecord struct {
	OIDCEmail          string    `json:"oidc_email"`
	TargetN8nEmail     string    `json:"target_n8n_email"`
	OriginalLocalEmail string    `json:"original_local_email"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// DB handles database queries on n8n_db.
type DB struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// NewDB creates a new DB instance.
func NewDB(ctx context.Context, dbURL string, log *slog.Logger) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect db pool: %w", err)
	}

	db := &DB{pool: pool, log: log.With("component", "auth-db")}
	if err := db.Init(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("init db schema: %w", err)
	}

	return db, nil
}

// Close closes the connection pool.
func (d *DB) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
	}
}

// Init ensures the n8n_auth_mappings table exists.
func (d *DB) Init(ctx context.Context) error {
	const query = `
		CREATE TABLE IF NOT EXISTS n8n_auth_mappings (
			oidc_email VARCHAR(255) PRIMARY KEY,
			target_n8n_email VARCHAR(255) NOT NULL,
			original_local_email VARCHAR(255),
			status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`
	_, err := d.pool.Exec(ctx, query)
	return err
}

// GetMapping returns the mapping record for an OIDC email, if any.
func (d *DB) GetMapping(ctx context.Context, oidcEmail string) (*MappingRecord, error) {
	const query = `
		SELECT oidc_email, target_n8n_email, COALESCE(original_local_email, ''), status, created_at, updated_at
		FROM n8n_auth_mappings
		WHERE LOWER(oidc_email) = LOWER($1) AND status = 'ACTIVE';
	`
	row := d.pool.QueryRow(ctx, query, strings.TrimSpace(oidcEmail))
	var m MappingRecord
	if err := row.Scan(&m.OIDCEmail, &m.TargetN8nEmail, &m.OriginalLocalEmail, &m.Status, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	return &m, nil
}

// ListMappings returns all mapping records.
func (d *DB) ListMappings(ctx context.Context) ([]MappingRecord, error) {
	const query = `
		SELECT oidc_email, target_n8n_email, COALESCE(original_local_email, ''), status, created_at, updated_at
		FROM n8n_auth_mappings
		ORDER BY created_at DESC;
	`
	rows, err := d.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []MappingRecord
	for rows.Next() {
		var m MappingRecord
		if err := rows.Scan(&m.OIDCEmail, &m.TargetN8nEmail, &m.OriginalLocalEmail, &m.Status, &m.CreatedAt, &m.UpdatedAt); err == nil {
			list = append(list, m)
		}
	}
	return list, nil
}

// DeleteMapping removes a mapping for an OIDC email.
func (d *DB) DeleteMapping(ctx context.Context, oidcEmail string) error {
	const query = `DELETE FROM n8n_auth_mappings WHERE LOWER(oidc_email) = LOWER($1);`
	_, err := d.pool.Exec(ctx, query, strings.TrimSpace(oidcEmail))
	return err
}

// ExecuteTakeover maps an OIDC user to replace a legacy local n8n user.
// All workflows and credentials previously owned by localEmail become owned by oidcEmail.
func (d *DB) ExecuteTakeover(ctx context.Context, oidcEmail, localEmail, firstName, lastName string) error {
	oidcEmail = strings.TrimSpace(strings.ToLower(oidcEmail))
	localEmail = strings.TrimSpace(strings.ToLower(localEmail))

	if oidcEmail == "" || localEmail == "" {
		return fmt.Errorf("both oidcEmail and localEmail are required")
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin takeover tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Verify local user exists
	var localUserID string
	err = tx.QueryRow(ctx, `SELECT id FROM "user" WHERE LOWER(email) = LOWER($1);`, localEmail).Scan(&localUserID)
	if err != nil {
		return fmt.Errorf("local user %q does not exist: %w", localEmail, err)
	}

	// 2. Check if OIDC user already exists in "user" table
	var oidcUserID string
	err = tx.QueryRow(ctx, `SELECT id FROM "user" WHERE LOWER(email) = LOWER($1);`, oidcEmail).Scan(&oidcUserID)

	if err != nil {
		// Skenario 1: OIDC user does NOT exist yet -> Direct rename/takeover
		d.log.Info("executing direct takeover (renaming local user)", "from", localEmail, "to", oidcEmail)

		if firstName == "" {
			firstName = "User"
		}
		if lastName == "" {
			lastName = "Lab"
		}

		projName := fmt.Sprintf("%s %s <%s>", firstName, lastName, oidcEmail)

		// Update "user" table
		_, err = tx.Exec(ctx, `
			UPDATE "user"
			SET email = $1, "firstName" = $2, "lastName" = $3, disabled = false, "updatedAt" = NOW()
			WHERE id = $4;
		`, oidcEmail, firstName, lastName, localUserID)
		if err != nil {
			return fmt.Errorf("update user record: %w", err)
		}

		// Update "project" name
		_, err = tx.Exec(ctx, `
			UPDATE project
			SET name = $1, "updatedAt" = NOW()
			WHERE id = (
				SELECT "projectId" FROM project_relation
				WHERE "userId" = $2 AND role = 'project:personalOwner'
			);
		`, projName, localUserID)
		if err != nil {
			return fmt.Errorf("update project name: %w", err)
		}
	} else {
		// Skenario 2: OIDC user ALREADY exists -> Transfer workflows and credentials
		d.log.Info("executing asset transfer (moving workflows & credentials)", "from", localEmail, "to", oidcEmail)

		// Get local user personal project ID
		var localProjID string
		err = tx.QueryRow(ctx, `
			SELECT "projectId" FROM project_relation
			WHERE "userId" = $1 AND role = 'project:personalOwner';
		`, localUserID).Scan(&localProjID)
		if err != nil {
			return fmt.Errorf("get local project id: %w", err)
		}

		// Get oidc user personal project ID
		var oidcProjID string
		err = tx.QueryRow(ctx, `
			SELECT "projectId" FROM project_relation
			WHERE "userId" = $1 AND role = 'project:personalOwner';
		`, oidcUserID).Scan(&oidcProjID)
		if err != nil {
			return fmt.Errorf("get oidc project id: %w", err)
		}

		// Move shared_workflow
		_, err = tx.Exec(ctx, `
			UPDATE shared_workflow
			SET "projectId" = $1, "updatedAt" = NOW()
			WHERE "projectId" = $2;
		`, oidcProjID, localProjID)
		if err != nil {
			return fmt.Errorf("move workflows: %w", err)
		}

		// Move shared_credentials
		_, err = tx.Exec(ctx, `
			UPDATE shared_credentials
			SET "projectId" = $1, "updatedAt" = NOW()
			WHERE "projectId" = $2;
		`, oidcProjID, localProjID)
		if err != nil {
			return fmt.Errorf("move credentials: %w", err)
		}

		// Disable legacy local user
		_, err = tx.Exec(ctx, `
			UPDATE "user"
			SET disabled = true, "updatedAt" = NOW()
			WHERE id = $1;
		`, localUserID)
		if err != nil {
			return fmt.Errorf("disable old user: %w", err)
		}
	}

	// 3. Upsert n8n_auth_mappings record
	_, err = tx.Exec(ctx, `
		INSERT INTO n8n_auth_mappings (oidc_email, target_n8n_email, original_local_email, status, updated_at)
		VALUES ($1, $1, $2, 'ACTIVE', NOW())
		ON CONFLICT (oidc_email) DO UPDATE
		SET target_n8n_email = EXCLUDED.target_n8n_email,
		    original_local_email = EXCLUDED.original_local_email,
		    status = 'ACTIVE',
		    updated_at = NOW();
	`, oidcEmail, localEmail)
	if err != nil {
		return fmt.Errorf("upsert mapping record: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit takeover tx: %w", err)
	}

	d.log.Info("account takeover completed successfully", "oidc", oidcEmail, "replaced", localEmail)
	return nil
}

// EnsureUserExists ensures an n8n user and their personal project exist in n8n_db.
//
// firstName/lastName come from the identity provider (empty when the account is created without a sign-in, e.g. as the
// target of an ownership transfer). A new account without names gets the placeholder from placeholderNames. An existing
// account whose names are still a placeholder is filled in with the identity provider's names the first time they are
// known; names that differ from a placeholder (the user changed them, or they were filled in before) are never touched.
func (d *DB) EnsureUserExists(ctx context.Context, email, firstName, lastName string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	var userID, curFirst, curLast string
	err := d.pool.QueryRow(ctx, `SELECT id, COALESCE("firstName", ''), COALESCE("lastName", '') FROM "user" WHERE LOWER(email) = LOWER($1);`, email).Scan(&userID, &curFirst, &curLast)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check user existence: %w", err)
	}
	if err == nil {
		return d.fillPlaceholderNames(ctx, userID, email, curFirst, curLast, firstName, lastName)
	}

	d.log.Info("JIT provisioning new user in n8n_db", "email", email)

	firstName, lastName = initialNames(email, firstName, lastName)

	// Generate a random initial password (will be overwritten by managed password)
	dummyPass := make([]byte, 16)
	_, _ = rand.Read(dummyPass)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(dummyPass)), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin jit user tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Insert user
	err = tx.QueryRow(ctx, `
		INSERT INTO "user" (email, "firstName", "lastName", password, "roleSlug", disabled, "mfaEnabled", "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, 'global:member', false, false, NOW(), NOW())
		RETURNING id;
	`, email, firstName, lastName, string(hashedPass)).Scan(&userID)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	// 2. Insert personal project (n8n project table id is varchar(36))
	projName := projectName(firstName, lastName, email)
	var projID string
	err = tx.QueryRow(ctx, `
		INSERT INTO project (id, name, type, "creatorId", "createdAt", "updatedAt")
		VALUES (gen_random_uuid()::text, $1, 'personal', $2, NOW(), NOW())
		RETURNING id;
	`, projName, userID).Scan(&projID)
	if err != nil {
		return fmt.Errorf("insert personal project: %w", err)
	}

	// 3. Insert project_relation
	_, err = tx.Exec(ctx, `
		INSERT INTO project_relation ("projectId", "userId", role, "createdAt", "updatedAt")
		VALUES ($1, $2, 'project:personalOwner', NOW(), NOW());
	`, projID, userID)
	if err != nil {
		return fmt.Errorf("insert project relation: %w", err)
	}

	return tx.Commit(ctx)
}

// fillPlaceholderNames replaces a placeholder name of an existing user (and the name of their personal project, when it
// still carries that placeholder) with the names the identity provider sent.
func (d *DB) fillPlaceholderNames(ctx context.Context, userID, email, curFirst, curLast, idpFirst, idpLast string) error {
	newFirst, newLast, ok := namesToFill(email, curFirst, curLast, idpFirst, idpLast)
	if !ok {
		return nil
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin fill names tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `UPDATE "user" SET "firstName" = $1, "lastName" = $2, "updatedAt" = NOW() WHERE id = $3;`, newFirst, newLast, userID); err != nil {
		return fmt.Errorf("update user names: %w", err)
	}
	// Only a project still named after the placeholder is renamed; a project the user renamed is left alone.
	if _, err := tx.Exec(ctx, `
		UPDATE project SET name = $1, "updatedAt" = NOW()
		WHERE type = 'personal' AND name = $2
		  AND id IN (SELECT "projectId" FROM project_relation WHERE "userId" = $3 AND role = 'project:personalOwner');
	`, projectName(newFirst, newLast, email), projectName(curFirst, curLast, email), userID); err != nil {
		return fmt.Errorf("update personal project name: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.log.Info("replaced placeholder name with identity provider name", "email", email)
	return nil
}

// EnsureManagedPassword sets the user's password to a known plain text password.
func (d *DB) EnsureManagedPassword(ctx context.Context, email, plainPassword string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash managed password: %w", err)
	}

	_, err = d.pool.Exec(ctx, `
		UPDATE "user"
		SET password = $1, "updatedAt" = NOW()
		WHERE LOWER(email) = LOWER($2);
	`, string(hashedPass), email)
	return err
}

// UserInfo represents summary information of an n8n user.
type UserInfo struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	FirstName         string    `json:"first_name"`
	LastName          string    `json:"last_name"`
	Role              string    `json:"role"`
	Disabled          bool      `json:"disabled"`
	PersonalProjectID string    `json:"personal_project_id"`
	CreatedAt         time.Time `json:"created_at"`
}

// TransferResult holds the outcome of a workflow/credential transfer.
type TransferResult struct {
	FromEmail              string `json:"from_email"`
	ToEmail                string `json:"to_email"`
	WorkflowsTransferred   int64  `json:"workflows_transferred"`
	CredentialsTransferred int64  `json:"credentials_transferred"`
	SourceDisabled         bool   `json:"source_disabled"`
	WorkflowID             string `json:"workflow_id,omitempty"`
}

// DeleteUserResult holds outcome of user deletion.
type DeleteUserResult struct {
	Email             string `json:"email"`
	PersonalProjectID string `json:"personal_project_id"`
	WorkflowsDeleted  int64  `json:"workflows_deleted"`
}

// IsUserDisabled checks whether an n8n user is disabled.
func (d *DB) IsUserDisabled(ctx context.Context, email string) (bool, error) {
	var disabled bool
	err := d.pool.QueryRow(ctx, `SELECT disabled FROM "user" WHERE LOWER(email) = LOWER($1);`, strings.TrimSpace(email)).Scan(&disabled)
	if err != nil {
		return false, err
	}
	return disabled, nil
}

// SetUserDisabled sets the disabled status of an n8n user.
func (d *DB) SetUserDisabled(ctx context.Context, email string, disabled bool) error {
	email = strings.TrimSpace(strings.ToLower(email))
	var roleSlug string
	err := d.pool.QueryRow(ctx, `SELECT "roleSlug" FROM "user" WHERE LOWER(email) = LOWER($1);`, email).Scan(&roleSlug)
	if err != nil {
		return fmt.Errorf("user %q not found: %w", email, err)
	}

	if roleSlug == "global:owner" && disabled {
		return fmt.Errorf("cannot disable instance owner (global:owner)")
	}

	d.log.Info("setting user disabled status", "email", email, "disabled", disabled)
	_, err = d.pool.Exec(ctx, `
		UPDATE "user"
		SET disabled = $1, "updatedAt" = NOW()
		WHERE LOWER(email) = LOWER($2);
	`, disabled, email)
	return err
}

// DeleteUser deletes an n8n user and their personal project safely.
func (d *DB) DeleteUser(ctx context.Context, email string, force bool) (*DeleteUserResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	var userID, roleSlug, projID string
	err := d.pool.QueryRow(ctx, `
		SELECT u.id, u."roleSlug", COALESCE(pr."projectId", '')
		FROM "user" u
		LEFT JOIN project_relation pr ON pr."userId" = u.id AND pr.role = 'project:personalOwner'
		WHERE LOWER(u.email) = LOWER($1);
	`, email).Scan(&userID, &roleSlug, &projID)
	if err != nil {
		return nil, fmt.Errorf("user %q not found: %w", email, err)
	}

	if roleSlug == "global:owner" {
		return nil, fmt.Errorf("cannot delete instance owner (global:owner)")
	}

	// Check workflow count if not forced
	var wfCount int64
	if projID != "" {
		_ = d.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM shared_workflow
			WHERE "projectId" = $1 AND role = 'workflow:owner';
		`, projID).Scan(&wfCount)

		if wfCount > 0 && !force {
			return nil, fmt.Errorf("user still owns %d workflow(s); transfer ownership first or set force=true to delete permanently", wfCount)
		}
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin delete user tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Remove mapping entry
	_, _ = tx.Exec(ctx, `
		DELETE FROM n8n_auth_mappings
		WHERE LOWER(oidc_email) = LOWER($1) OR LOWER(target_n8n_email) = LOWER($1);
	`, email)

	// 2. Remove personal project and cascade relations
	if projID != "" {
		_, _ = tx.Exec(ctx, `DELETE FROM shared_workflow WHERE "projectId" = $1;`, projID)
		_, _ = tx.Exec(ctx, `DELETE FROM shared_credentials WHERE "projectId" = $1;`, projID)
		_, _ = tx.Exec(ctx, `DELETE FROM project_relation WHERE "projectId" = $1 OR "userId" = $2;`, projID, userID)
		_, _ = tx.Exec(ctx, `DELETE FROM project WHERE id = $1 AND type = 'personal';`, projID)
	}

	// 3. Delete user record
	_, err = tx.Exec(ctx, `DELETE FROM "user" WHERE id = $1;`, userID)
	if err != nil {
		return nil, fmt.Errorf("delete user record: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delete user tx: %w", err)
	}

	d.log.Info("user deleted successfully", "email", email, "workflows_deleted", wfCount)
	return &DeleteUserResult{
		Email:             email,
		PersonalProjectID: projID,
		WorkflowsDeleted:  wfCount,
	}, nil
}

// SyncUserRole synchronizes an n8n user's roleSlug with Keycloak (global:admin or global:member).
// It preserves global:owner role (initial instance root/owner).
func (d *DB) SyncUserRole(ctx context.Context, email, targetRole string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	targetRole = strings.TrimSpace(targetRole)
	if targetRole != "global:admin" && targetRole != "global:member" {
		return fmt.Errorf("invalid target role: %s (must be global:admin or global:member)", targetRole)
	}

	var currentRole string
	err := d.pool.QueryRow(ctx, `SELECT "roleSlug" FROM "user" WHERE LOWER(email) = LOWER($1);`, email).Scan(&currentRole)
	if err != nil {
		return fmt.Errorf("user %q not found: %w", email, err)
	}

	if currentRole == "global:owner" {
		d.log.Info("preserving global:owner role for user", "email", email)
		return nil
	}

	if currentRole == targetRole {
		return nil
	}

	d.log.Info("updating user role in n8n_db", "email", email, "old_role", currentRole, "new_role", targetRole)
	_, err = d.pool.Exec(ctx, `
		UPDATE "user"
		SET "roleSlug" = $1, "updatedAt" = NOW()
		WHERE LOWER(email) = LOWER($2);
	`, targetRole, email)
	return err
}

// ListUsers returns all users in n8n_db along with their personal project ID.
func (d *DB) ListUsers(ctx context.Context) ([]UserInfo, error) {
	const query = `
		SELECT u.id, COALESCE(u.email, ''), COALESCE(u."firstName", ''), COALESCE(u."lastName", ''),
		       u."roleSlug", u.disabled, COALESCE(pr."projectId", ''), u."createdAt"
		FROM "user" u
		LEFT JOIN project_relation pr ON pr."userId" = u.id AND pr.role = 'project:personalOwner'
		ORDER BY u."createdAt" ASC;
	`
	rows, err := d.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var list []UserInfo
	for rows.Next() {
		var u UserInfo
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.Disabled, &u.PersonalProjectID, &u.CreatedAt); err == nil {
			list = append(list, u)
		}
	}
	return list, nil
}

// TransferOwnership transfers workflows and credentials between any two n8n accounts.
func (d *DB) TransferOwnership(ctx context.Context, fromEmail, toEmail string, disableSource bool, workflowID string) (*TransferResult, error) {
	fromEmail = strings.TrimSpace(strings.ToLower(fromEmail))
	toEmail = strings.TrimSpace(strings.ToLower(toEmail))
	workflowID = strings.TrimSpace(workflowID)

	if fromEmail == "" || toEmail == "" {
		return nil, fmt.Errorf("both from_email and to_email are required")
	}
	if fromEmail == toEmail {
		return nil, fmt.Errorf("from_email and to_email cannot be the same")
	}

	// 0. Auto-provision target user and personal project if they have never logged in yet
	if err := d.EnsureUserExists(ctx, toEmail, "", ""); err != nil {
		return nil, fmt.Errorf("auto-provision target user %q: %w", toEmail, err)
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transfer tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Get source user and project ID
	var fromUserID, fromProjID string
	err = tx.QueryRow(ctx, `
		SELECT u.id, pr."projectId"
		FROM "user" u
		JOIN project_relation pr ON pr."userId" = u.id AND pr.role = 'project:personalOwner'
		WHERE LOWER(u.email) = LOWER($1);
	`, fromEmail).Scan(&fromUserID, &fromProjID)
	if err != nil {
		return nil, fmt.Errorf("source user %q not found or has no personal project: %w", fromEmail, err)
	}

	// 2. Get target user and project ID
	var toUserID, toProjID string
	err = tx.QueryRow(ctx, `
		SELECT u.id, pr."projectId"
		FROM "user" u
		JOIN project_relation pr ON pr."userId" = u.id AND pr.role = 'project:personalOwner'
		WHERE LOWER(u.email) = LOWER($1);
	`, toEmail).Scan(&toUserID, &toProjID)
	if err != nil {
		return nil, fmt.Errorf("target user %q not found or has no personal project: %w", toEmail, err)
	}

	res := &TransferResult{
		FromEmail:      fromEmail,
		ToEmail:        toEmail,
		SourceDisabled: disableSource,
		WorkflowID:     workflowID,
	}

	// 3. Transfer workflows
	if workflowID != "" {
		// Single workflow transfer
		// Remove target project relation on this workflow if already shared (to prevent primary key conflict)
		_, _ = tx.Exec(ctx, `
			DELETE FROM shared_workflow
			WHERE "projectId" = $1 AND "workflowId" = $2;
		`, toProjID, workflowID)

		tag, err := tx.Exec(ctx, `
			UPDATE shared_workflow
			SET "projectId" = $1, role = 'workflow:owner', "updatedAt" = NOW()
			WHERE "projectId" = $2 AND "workflowId" = $3;
		`, toProjID, fromProjID, workflowID)
		if err != nil {
			return nil, fmt.Errorf("transfer workflow %s: %w", workflowID, err)
		}
		res.WorkflowsTransferred = tag.RowsAffected()
	} else {
		// All workflows transfer
		// Delete any existing share entries for target project on workflows owned by source project
		_, err = tx.Exec(ctx, `
			DELETE FROM shared_workflow
			WHERE "projectId" = $1
			  AND "workflowId" IN (SELECT "workflowId" FROM shared_workflow WHERE "projectId" = $2);
		`, toProjID, fromProjID)
		if err != nil {
			return nil, fmt.Errorf("clean existing target workflow shares: %w", err)
		}

		tagWf, err := tx.Exec(ctx, `
			UPDATE shared_workflow
			SET "projectId" = $1, role = 'workflow:owner', "updatedAt" = NOW()
			WHERE "projectId" = $2;
		`, toProjID, fromProjID)
		if err != nil {
			return nil, fmt.Errorf("transfer all workflows: %w", err)
		}
		res.WorkflowsTransferred = tagWf.RowsAffected()

		// Transfer all credentials
		_, err = tx.Exec(ctx, `
			DELETE FROM shared_credentials
			WHERE "projectId" = $1
			  AND "credentialsId" IN (SELECT "credentialsId" FROM shared_credentials WHERE "projectId" = $2);
		`, toProjID, fromProjID)
		if err != nil {
			return nil, fmt.Errorf("clean existing target credential shares: %w", err)
		}

		tagCred, err := tx.Exec(ctx, `
			UPDATE shared_credentials
			SET "projectId" = $1, role = 'credential:owner', "updatedAt" = NOW()
			WHERE "projectId" = $2;
		`, toProjID, fromProjID)
		if err != nil {
			return nil, fmt.Errorf("transfer all credentials: %w", err)
		}
		res.CredentialsTransferred = tagCred.RowsAffected()
	}

	// 4. Optionally disable source user
	if disableSource {
		_, err = tx.Exec(ctx, `
			UPDATE "user"
			SET disabled = true, "updatedAt" = NOW()
			WHERE id = $1;
		`, fromUserID)
		if err != nil {
			return nil, fmt.Errorf("disable source user: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transfer tx: %w", err)
	}

	d.log.Info("transfer ownership completed", "from", fromEmail, "to", toEmail,
		"workflows", res.WorkflowsTransferred, "credentials", res.CredentialsTransferred, "disabled", disableSource)
	return res, nil
}
