# L3ak CTF 2024
Competition URL: https://ctf.l3ak.team/
## Overview

| Challenge       | Category | Points | Solves | Flag                                       |
| --------------- | -------- | ------ | ------ | ------------------------------------------ |
| Windows-1252    | misc     |  498   |    9   | L3AK{0pT!cal_chaR4Ct3R_R3cOgN!tIon_i5_fUN} |

## Challenge Author:
- [Matthias](https://github.com/0x-Matthias/)

## Challenge: Windows-1252
How fast do you think you can solve captchas?

## Overview
This challenge is all about automating to solve captchas, which are using the Windows-1252 character set, as hinted to in the challenge name.

As there's multiple ways to do this, we'll share two sample implementations using different techniques:
1. [Using pure image manipualtion](./Image-Manipulation-Solve/README.md)
2. [Using AI](./CNN-Solve/Windows%201252%20Walkthrough.pdf)

### Additional information
1. The character images and the noise patterns used by the server instance used during the CTF have been pregenerated and used as static assets. This way we could assure a working solution using image manipulation and improve performance on the server.
2. The Dockerfile, bundled in the [build](../build/) directory, contains instructions how to deploy (i.e. build and run) the server as a docker container. This basically boils down to running the following commands from within the [build](../build/) directory of the challenge:
   ```Dockerfile
   docker build -t l3ak_ctf_2024_misc_windows-1252 .
   docker run -d --rm -p 8448:8448 l3ak_ctf_2024_misc_windows-1252
   ```

## Resources
- [Wikipedia: Windows-1252 Codepage layout](https://en.wikipedia.org/wiki/Windows-1252#Codepage_layout)