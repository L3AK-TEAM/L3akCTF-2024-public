const ALLOWED_TAGS = [
    'a',     
    'b',      
    'i',    
    'u',     
    'strong', 
    'em',     
    'p',      
    'h1',     
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'br',     
    'span',   
    'div'     
];

htmx.on("htmx:beforeSwap", (event) => {
    if (event.detail.target.id.startsWith("note")) {
        event.detail.serverResponse = DOMPurify.sanitize(event.detail.serverResponse, {ALLOWED_TAGS: ALLOWED_TAGS});
    }
});

htmx.on("clear-notes", () => {
    document.getElementById("notes-container").innerHTML = "";
});

htmx.on("load-notes", () => {
    htmx.ajax("GET", "/api/notes", "#notes-container");
});

htmx.on('not-logged-in', () => {
    alert("You must be logged in to perform this action.");
});

htmx.on("note-too-long", () => {
    alert("Note is too long. Please keep it under 256 characters.");
})

htmx.on("login-failed", () => {
    alert("Invalid username or password. Please try again.");
})

htmx.on("registration-failed", () => {
    alert("Registration failed. Please try again.");
})
