package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func initDB(filepath string) *sql.DB {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	initDbSQL := `
	DROP TABLE IF EXISTS users;
	DROP TABLE IF EXISTS notes;

	CREATE TABLE IF NOT EXISTS users (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"username" TEXT NOT NULL UNIQUE,
		"password" TEXT NOT NULL
	);
		  
	CREATE TABLE IF NOT EXISTS notes (
		"id" TEXT PRIMARY KEY NOT NULL UNIQUE,
		"content" TEXT,
		"owner" INTEGER,
		FOREIGN KEY("owner") REFERENCES users("id")
	);
	`

	_, err = db.Exec(initDbSQL)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}

	return db
}

func clearNotes(db *sql.DB) {
    _, err := db.Exec("DELETE FROM notes")
    if err != nil {
        log.Fatalf("Error clearing notes: %v", err)
    }
}

func InsertUser(db *sql.DB, auth Auth) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(auth.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", auth.Username, hashedPassword)
	return err
}

func GetUser(db *sql.DB, auth Auth) (int, error) {
	var id int
	var hashedPassword []byte

	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", auth.Username, hashedPassword).Scan(&id, &hashedPassword)
	if err != nil {
		return -1, err
	}
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(auth.Password))
	return id, err
}

func GetNoteByUUID(db *sql.DB, id string) (Note, error) {
	var note Note
	err := db.QueryRow("SELECT id, content FROM notes WHERE id = ?", id).Scan(&note.ID, &note.Content)
	return note, err
}

func GetNotes(db *sql.DB, owner int) ([]Note, error) {
	rows, err := db.Query("SELECT id, content FROM notes WHERE owner = ? LIMIT 30", owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	notes := []Note{}
	for rows.Next() {
		var note Note
		if err := rows.Scan(&note.ID, &note.Content); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}

	return notes, nil
}

func InsertNote(db *sql.DB, note Note) error {
	_, err := db.Exec("INSERT INTO notes (id, content, owner) VALUES (?, ?, ?)", note.ID, note.Content, note.Owner)
	return err
}
