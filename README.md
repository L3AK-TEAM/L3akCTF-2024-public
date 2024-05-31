# L3akCTF 2024 


Repository for L3akCTF 2024, please follow the following specification to contribute to the repository.

---


## How To Add a Challenge
When making a challenge, please follow the following specifications:
- First, **make a new branch** with the name category/challenge-name (`git checkout -b category/challenge-name`)
- In your branch, please create a new directory called `challenge-name` (replacing the name of your challenge) in the corresponding category directory.
- Create a `README.md` file in your challenge directory with the challenge description.
    - This README should contain the challenge description, flag format, and any other relevant information.
    - Make sure that it is detailed enough so we can add it with the appropriate description to the CTF platform.
- In your challenge directory, create a `build` directory with a `Dockerfile` to build the challenge.
    - Make sure that this directory contains all the necessary files to build the challenge.
- If your challenge requires a handout, please put all attachment related files in the `dist` directory
- If you have any solve scripts, writeups, or other solution-related files, please put them in the `solution` directory.

- Create a `chal.<category>.<name>.yml` file in the `.github/workflows/` directory to build the challenge. Ignore this step for now.

Once made, please push your branch to the repository and create a pull request to merge it into the main branch.

Please follow the below specified file structure to add a challenge.

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
