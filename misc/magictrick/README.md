# Magic Trick

**Author:** ahh

**Difficulty:** medium

**Category:** Misc

## Description
I will take your code, and make it disappear!

## Deployment
```sh
docker run -p 5000:5000 --privileged $(docker build -q .)
```