package store

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db *sql.DB
	mu sync.RWMutex
}

func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	log.Printf("[store] opened database at %s", path)
	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS subscribers (
			username TEXT NOT NULL,
			domain TEXT NOT NULL,
			ha1 TEXT NOT NULL,
			ha1b TEXT NOT NULL DEFAULT '',
			password TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (username, domain)
		)`,
		`CREATE TABLE IF NOT EXISTS location (
			aor TEXT NOT NULL,
			contact TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			received_ip TEXT NOT NULL DEFAULT '',
			received_port INTEGER NOT NULL DEFAULT 0,
			transport TEXT NOT NULL DEFAULT 'UDP',
			user_agent TEXT NOT NULL DEFAULT '',
			call_id TEXT NOT NULL DEFAULT '',
			cseq INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (aor, contact)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_location_aor ON location(aor)`,
		`CREATE INDEX IF NOT EXISTS idx_location_expires ON location(expires_at)`,
	}

	for _, m := range migrations {
		if _, err := d.db.Exec(m); err != nil {
			return err
		}
	}
	return nil
}

type Subscriber struct {
	Username string
	Domain   string
	HA1      string
	HA1B     string
	Password string
}

func (d *DB) GetSubscriber(username, domain string) (*Subscriber, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRow(
		"SELECT username, domain, ha1, ha1b, password FROM subscribers WHERE username = ? AND domain = ?",
		username, domain,
	)

	s := &Subscriber{}
	if err := row.Scan(&s.Username, &s.Domain, &s.HA1, &s.HA1B, &s.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return s, nil
}

func (d *DB) UpsertSubscriber(s *Subscriber) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT INTO subscribers (username, domain, ha1, ha1b, password)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username, domain) DO UPDATE SET ha1=excluded.ha1, ha1b=excluded.ha1b, password=excluded.password`,
		s.Username, s.Domain, s.HA1, s.HA1B, s.Password,
	)
	return err
}

func (d *DB) DeleteSubscriber(username, domain string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM subscribers WHERE username = ? AND domain = ?", username, domain)
	return err
}

func (d *DB) ListSubscribers(domain string) ([]*Subscriber, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var rows *sql.Rows
	var err error
	if domain != "" {
		rows, err = d.db.Query("SELECT username, domain, ha1, ha1b, password FROM subscribers WHERE domain = ? ORDER BY username", domain)
	} else {
		rows, err = d.db.Query("SELECT username, domain, ha1, ha1b, password FROM subscribers ORDER BY username, domain")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Subscriber
	for rows.Next() {
		s := &Subscriber{}
		if err := rows.Scan(&s.Username, &s.Domain, &s.HA1, &s.HA1B, &s.Password); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, nil
}

type Binding struct {
	AOR          string
	Contact      string
	ExpiresAt    time.Time
	ReceivedIP   string
	ReceivedPort int
	Transport    string
	UserAgent    string
	CallID       string
	CSeq         int
}

func (d *DB) SaveBinding(b *Binding) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT INTO location (aor, contact, expires_at, received_ip, received_port, transport, user_agent, call_id, cseq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(aor, contact) DO UPDATE SET
		   expires_at=excluded.expires_at,
		   received_ip=excluded.received_ip,
		   received_port=excluded.received_port,
		   transport=excluded.transport,
		   user_agent=excluded.user_agent,
		   call_id=excluded.call_id,
		   cseq=excluded.cseq`,
		b.AOR, b.Contact, b.ExpiresAt.Unix(), b.ReceivedIP, b.ReceivedPort, b.Transport, b.UserAgent, b.CallID, b.CSeq,
	)
	return err
}

func (d *DB) DeleteBinding(aor, contact string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM location WHERE aor = ? AND contact = ?", aor, contact)
	return err
}

func (d *DB) DeleteAllBindings(aor string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM location WHERE aor = ?", aor)
	return err
}

func (d *DB) LookupBindings(aor string) ([]*Binding, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().Unix()
	rows, err := d.db.Query(
		"SELECT aor, contact, expires_at, received_ip, received_port, transport, user_agent, call_id, cseq FROM location WHERE aor = ? AND expires_at > ?",
		aor, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Binding
	for rows.Next() {
		b := &Binding{}
		var expiresUnix int64
		if err := rows.Scan(&b.AOR, &b.Contact, &expiresUnix, &b.ReceivedIP, &b.ReceivedPort, &b.Transport, &b.UserAgent, &b.CallID, &b.CSeq); err != nil {
			return nil, err
		}
		b.ExpiresAt = time.Unix(expiresUnix, 0)
		result = append(result, b)
	}
	return result, nil
}

func (d *DB) ListAllBindings() ([]*Binding, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().Unix()
	rows, err := d.db.Query(
		"SELECT aor, contact, expires_at, received_ip, received_port, transport, user_agent, call_id, cseq FROM location WHERE expires_at > ? ORDER BY aor",
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Binding
	for rows.Next() {
		b := &Binding{}
		var expiresUnix int64
		if err := rows.Scan(&b.AOR, &b.Contact, &expiresUnix, &b.ReceivedIP, &b.ReceivedPort, &b.Transport, &b.UserAgent, &b.CallID, &b.CSeq); err != nil {
			return nil, err
		}
		b.ExpiresAt = time.Unix(expiresUnix, 0)
		result = append(result, b)
	}
	return result, nil
}

// ExpireBindings deletes every binding whose expires_at is in the
// past and returns those entries as they were just before deletion.
// Used by the registrar's expiry sweeper to emit reg-expired events.
func (d *DB) ExpireBindings() ([]*Binding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().Unix()
	rows, err := d.db.Query(
		"SELECT aor, contact, expires_at, received_ip, received_port, transport, user_agent, call_id, cseq FROM location WHERE expires_at <= ?",
		now,
	)
	if err != nil {
		return nil, err
	}

	var expired []*Binding
	for rows.Next() {
		b := &Binding{}
		var expiresUnix int64
		if err := rows.Scan(&b.AOR, &b.Contact, &expiresUnix, &b.ReceivedIP, &b.ReceivedPort, &b.Transport, &b.UserAgent, &b.CallID, &b.CSeq); err != nil {
			rows.Close()
			return nil, err
		}
		b.ExpiresAt = time.Unix(expiresUnix, 0)
		expired = append(expired, b)
	}
	rows.Close()

	if len(expired) > 0 {
		if _, err := d.db.Exec("DELETE FROM location WHERE expires_at <= ?", now); err != nil {
			return expired, err
		}
	}
	return expired, nil
}

func (d *DB) PurgeExpired() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	result, err := d.db.Exec("DELETE FROM location WHERE expires_at <= ?", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
