## gitlab-ci-image-scanner (gcis)
- Scrapes all GitLab `gitlab-ci.yml` files in all Groups API token has access to
- Identifies Docker images in use
- Executes security scan
- Provides reports
  - List of Docker images per Gitlab Project
  - Scan results of unique Docker Images

![](readme.gif)

### Usage
1. Compile
```
go mod init gcis
go get -d ./...
go build
```
  
2. Generate your GitLab Personal Access Token and export
```
export GITLAB_PAT="abc123"
```
  
3. Run `gcis`
```
❯ ./gcis -h
Usage of ./gcis:
  -file string
        Filename to dump from Git repo (default ".gitlab-ci.yml")
  -ref string
        Git Ref (Branch, Tag, Commit) to dump data from (default "main")
  -trivy
        Enable trivy scan
```
  
4. Check `gcis` reports
- `imagelist-TIMESTAMP.md` listing all identified images
- `scan-TIMESTAMP.md` reporting image vulnerabilities
  
### Sample gcis run
```
❯ gcis -trivy
✅ Trivy detected

Scanning files: ".gitlab-ci.yml" in Git Refs: "main" 

Project found, webUrl: https://gitlab.com/group2priv/g2p1priv 
Project found, webUrl: https://gitlab.com/group11220/g1p2 
Project found, webUrl: https://gitlab.com/group11220/g1p1 
Project found, webUrl: https://gitlab.com/jkosik/ci-snippets 
Project found, webUrl: https://gitlab.com/jkosik/blog 

❌ https://gitlab.com/group2priv/g2p1priv/-/raw/main/.gitlab-ci.yml is NOT reachable (503-Service Unavailable) 
✅ https://gitlab.com/group11220/g1p2/-/raw/main/.gitlab-ci.yml IS reachable (200-OK) 
✅ https://gitlab.com/group11220/g1p1/-/raw/main/.gitlab-ci.yml IS reachable (200-OK) 
✅ https://gitlab.com/jkosik/ci-snippets/-/raw/main/.gitlab-ci.yml IS reachable (200-OK) 
❌ https://gitlab.com/jkosik/blog/-/raw/main/.gitlab-ci.yml is NOT reachable (503-Service Unavailable) 

Scraping  https://gitlab.com/group11220/g1p2 https://gitlab.com/group11220/g1p2/-/raw/main/.gitlab-ci.yml
Scraping  https://gitlab.com/group11220/g1p1 https://gitlab.com/group11220/g1p1/-/raw/main/.gitlab-ci.yml
Scraping  https://gitlab.com/jkosik/ci-snippets https://gitlab.com/jkosik/ci-snippets/-/raw/main/.gitlab-ci.yml

➜ https://gitlab.com/group11220/g1p2 (.gitlab-ci.yml) 
    ➜  busybox
    ➜  haproxy:lts-bullseye
    ➜  haproxy:lts-alpine
    ➜  haproxy:2.7-dev0
➜ https://gitlab.com/group11220/g1p1 (.gitlab-ci.yml) 
    ➜  busybox
    ➜  nginx:1.22
    ➜  nginx:1.21.6
    ➜  nginx:1.21
➜ https://gitlab.com/jkosik/ci-snippets (.gitlab-ci.yml) 
    ➜  busybox
    ➜  nginx
    ➜  img2-indented-shifted
    ➜  img3-indented
    ➜  img4-normal
    ➜  img5-shifted
    ➜  img6-shifted-trailingspaces
    ➜  img9-stringafter
    ➜  img10-sgringafter-trailingspace

Image list saved to ./imagelist-20220612T101353Z.md 

Running Trivy scans...

↦ Scanning busybox...

2022-06-12T12:13:59.486+0200    INFO    Number of language-specific files: 0

↦ Scanning haproxy:lts-bullseye...

2022-06-12T12:14:01.424+0200    INFO    Detected OS: debian
2022-06-12T12:14:01.424+0200    INFO    Detecting Debian vulnerabilities...
2022-06-12T12:14:01.444+0200    INFO    Number of language-specific files: 0

haproxy:lts-bullseye (debian 11.3)
==================================
Total: 16 (HIGH: 13, CRITICAL: 3)

...snipped...

Trivy scans saved to scans-* directory. Empty scan results and failed scans have been removed.
```
  
  ### Further information
- Mind rate-limits on image pulls