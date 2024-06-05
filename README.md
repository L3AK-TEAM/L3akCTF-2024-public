# L3akCTF 2024 

Welcome to the official L3ak CTF 2024 challenge repo

---

## File Structure
This repository is structured as follows:
```
.github/workflows/                      # github actions
    └── chal.<category>.<name>.yml      # Build scripts

category1/                              # Category (ex: pwn, rev)
    ├── challenge1/
    |   ├── compose/                    # Challenge building directory (MULTI CONTAINER CHALLENGES)
    │   ├── build/                      # Challenge building directory (ONLY FOR SINGLE IMAGE CHALLS)
    │   │   ├── Dockerfile
    │   │   └── more...
    │   ├── dist/                       # Challenge handout (empty directory if nothing)
    |   ├── solution/                   # Challenge solution (scripts, writeups, etc)
    │   └── README.md                   # Challenge description
    ├── challenge2/
    └── more...

category2/                             
    ├── challenge3/
    │   ├── build/                     
    │   │   ├── Dockerfile
    │   │   └── more...
    │   ├── dist/                       
    │   ├── solution/                       
    │   └── README.md                  
    └── more...

more...
```
