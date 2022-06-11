## gitlab-ci-image-scanner (gcis)
- scrapes all GitLab `gitlab-ci.yml` files
- identifies Docker images in use
- executes security scan
- provide reports

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
