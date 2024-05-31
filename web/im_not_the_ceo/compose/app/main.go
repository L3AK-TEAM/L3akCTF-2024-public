package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/google/uuid"
)

type Note struct {
    ID      uuid.UUID
    Content template.HTML
    Owner   int
}

type Auth struct {
    Username string
    Password string
}

var key = make([]byte, 32)
var store *sessions.CookieStore
var db *sql.DB

var indexTmpl = template.Must(template.ParseFiles("templates/index.html"))
var loginTmpl = template.Must(template.ParseFiles("templates/login.html"))
var registerTmpl = template.Must(template.ParseFiles("templates/register.html"))
var viewTmpl = template.Must(template.ParseFiles("templates/view.html"))
var noteTmpl = template.Must(template.ParseFiles("templates/note.html"))

func startClearingNotesEvery30Mins(db *sql.DB) {
    go func() {
        for {
            clearNotes(db)
            time.Sleep(30 * time.Minute)
        }
    }()
}

func main() {
	rand.Read(key)
	store = sessions.NewCookieStore(key)

	db = initDB("notes.db")
	defer db.Close()

	startClearingNotesEvery30Mins(db)

	router := mux.NewRouter()

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		indexTmpl.Execute(w, nil)
	})

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
		} else {
			loginTmpl.Execute(w, nil)
		}
	})

	router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			session, _ := store.Get(r, "session")
			delete(session.Values, "id")
			delete(session.Values, "authenticated")
			session.Save(r, w)
			w.Header().Set("HX-Redirect", "/")
		}
	})

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerTmpl.Execute(w, nil)
	})

	router.HandleFunc("/api/login", loginHandler)
	router.HandleFunc("/api/notes", notesHandler)
	router.HandleFunc("/api/register", registerHandler)
	router.HandleFunc("/api/loginState", initLoginState)

	router.HandleFunc("/view/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		viewTmpl.Execute(w, vars["uuid"])
	})

	router.HandleFunc("/api/note/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("HX-Request") != "true" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		vars := mux.Vars(r)
		note, err := GetNoteByUUID(db, vars["uuid"])
		if err != nil {
			http.Error(w, "Note not found", http.StatusNotFound)
			return
		}
		noteTmpl.Execute(w, []Note{ note })
	})

	fmt.Println("Server listening on :8080...")
	http.ListenAndServe(":8080", router)
}

func initLoginState(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		w.Header().Set("HX-Trigger", "load-notes")
		fmt.Fprintf(w, "<button hx-get='/logout'>Logout</button>")
	} else {
		w.Header().Set("HX-Trigger", "clear-notes")
		fmt.Fprintf(w, "<button hx-get='/login'>Login</button>")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var auth Auth
	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := GetUser(db, auth)
	if err != nil {
		w.Header().Set("HX-Trigger", "login-failed")
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["id"] = id
	session.Values["authenticated"] = true
	session.Save(r, w)

	w.Header().Set("HX-Redirect", "/")
	fmt.Fprintf(w, "Login successful")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var auth Auth
	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := InsertUser(db, auth)
	if err != nil {
		w.Header().Set("HX-Trigger", "registration-failed")
		return
	}

	w.Header().Set("HX-Redirect", "/login")
	fmt.Fprintf(w, "Registration successful")
}

func notesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		w.Header().Set("HX-Trigger", "clear-notes, not-logged-in")
		return
	}

	switch r.Method {
	case "GET":
		notes, err := GetNotes(db, session.Values["id"].(int))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		noteTmpl.Execute(w, notes)

	case "POST":
		var newNote Note
		if err := json.NewDecoder(r.Body).Decode(&newNote); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if len(newNote.Content) > 256 {
			w.Header().Set("HX-Trigger", "note-too-long")
			return
		}

		newNote.ID = uuid.New()
		newNote.Owner = session.Values["id"].(int)

		err := InsertNote(db, newNote)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("HX-Redirect", "/view/" + newNote.ID.String())
		noteTmpl.Execute(w, []Note{newNote})
	}
}
