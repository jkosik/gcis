package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/xanzy/go-gitlab"
)

var currentTimeStamp string

func main() {
	timeStamp()

	// CLI Flag parsing
	fileName := flag.String("file", ".gitlab-ci.yml", "Filename to dump from Git repo")
	gitRef := flag.String("ref", "main", "Git Ref (Branch, Tag, Commit) to dump data from")
	trivy := flag.Bool("trivy", false, "Enable trivy scan")

	flag.Parse()

	// Check GITLAB_PAT env
	pat, pat_present := os.LookupEnv("GCIS_PAT")
	if !pat_present {
		fmt.Println("GCIS_PAT environment does not exist. Please generate GitLab Personal Access Token and export as GCIS_PAT")
		os.Exit(1)
	}

	// Check if Trivy is installed
	if *trivy {
		checkTrivy()
	}

	// Init go-gitlab
	git, err := gitlab.NewClient(pat)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// List Gitlab projects and grab Project's webUrls.
	opt := &gitlab.ListProjectsOptions{
		Owned:   gitlab.Bool(true),
		OrderBy: gitlab.String("path"),
	}
	projects, _, err := git.Projects.ListProjects(opt)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("Scanning files: \"%s\" in Git Refs: \"%s\" \n", *fileName, *gitRef)
	fmt.Println("")

	var webUrls []string // e.g. https://gitlab.com/jkosik/ci-snippets
	for i, _ := range projects {
		//fmt.Println(i, p, "\n")
		fmt.Printf("Project webUrl found: %s \n", projects[i].WebURL)
		webUrls = append(webUrls, projects[i].WebURL)
	}

	fmt.Println("")

	// Populating live urls (response code 200) from: Project webUrls => rawUrls => liveRawUrls
	rawUrls := make(map[string]string)
	liveRawUrls := make(map[string]string)

	for i, _ := range webUrls {
		rawUrl := webUrls[i] + "/-/raw/" + *gitRef + "/" + *fileName
		// webURL used as a rawUrls map Key
		// rawURL used as a rawUrls map Value
		// e.g. {url: url/-/raw/main/.gitlab-ci.yml}
		url := webUrls[i]
		rawUrls[url] = rawUrl

		// Test response code 200 for rawUrls and generate liveRawUrls
		resp, err := http.Get(rawUrls[url])
		if err != nil {
			log.Fatal(err)
		}

		if resp.StatusCode == 200 {
			fmt.Printf("\u2705 %s IS reachable (%d-%s) \n", rawUrls[url], resp.StatusCode, http.StatusText(resp.StatusCode))
			// populate liveRawUrls as a subset of rawUrls for response codes 200
			liveRawUrls[url] = rawUrl
		} else {
			fmt.Printf("\u274C %s is NOT reachable (%d-%s) \n", rawUrls[url], resp.StatusCode, http.StatusText(resp.StatusCode))
		}

		defer resp.Body.Close()
	}

	fmt.Println("")

	// Scarping all "image" directives from file
	imageMap := make(map[string][]string) // map of slices, e.g. {"url": {"image1", "image2"}
	for url, rawurl := range liveRawUrls {
		fmt.Println("Scraping ", url, rawurl)
		resp, err := http.Get(rawurl)
		if err != nil {
			log.Fatal(err)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		// Print scraped file
		// fmt.Println(string(b))

		// Relying on Gitlab and Yaml syntax. Evaulating only viable options.
		// No non-whitespace chars before "image:" (skips also commented lines).
		// 1+ whitespaces needed after "image:"
		regexp, _ := regexp.Compile(`(?m)^\s*image:\s+\S+`)
		validImages := regexp.FindAllString(string(b), -1)

		// Saving clean image names into imageMap
		for _, imageFullLine := range validImages {
			imageNameWhitespaced := strings.ReplaceAll(imageFullLine, "image:", "")
			// fmt.Println(imageFullLine)
			imageName := strings.ReplaceAll(imageNameWhitespaced, " ", "")
			// fmt.Println(imageName)
			// Populate map of urls and corresponding slice of images found in the scraped file
			imageMap[url] = append(imageMap[url], imageName)
		}

		defer resp.Body.Close()
	}

	fmt.Println("")

	// Save scrape results to file
	imageListFileName := "imagelist-" + currentTimeStamp + ".md"
	f, err := os.Create(imageListFileName)
	check(err)

	defer f.Close()

	for k, v := range imageMap {
		fmt.Printf("\u279C %s (%s) \n", k, *fileName)
		_, err := f.WriteString("### " + k + " (" + *fileName + ")" + "\n")
		check(err)
		for _, image := range v {
			fmt.Println("    \u279C ", image)
			_, err := f.WriteString(image + "  \n") // double space for markdown newline
			check(err)
			f.Sync()
		}
		fmt.Printf("")
	}
	fmt.Printf("")
	fmt.Printf("Image list saved as ./%s \n", imageListFileName)
	fmt.Printf("")

	// Run Trivy
	if *trivy {
		runTrivy()
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func timeStamp() {
	ts := time.Now().UTC().Format(time.RFC3339)
	currentTimeStamp = strings.Replace(strings.Replace(ts, ":", "", -1), "-", "", -1)
}

func checkTrivy() {
	cmd := exec.Command("trivy", "-h")

	_, err := cmd.Output()
	if err != nil {
		fmt.Println("\u274C Trivy not ready")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("\u2705 Trivy detected")
	fmt.Println("")
}

func runTrivy() {
	scanFileName := "scan-" + currentTimeStamp
	args := []string{"image", "-s", "HIGH,CRITICAL", "-f", "table", "-o", scanFileName, "nginx"}
	cmd := exec.Command("trivy", args...)

	cmdOut, err := cmd.Output()
	if err != nil {
		switch e := err.(type) {
		case *exec.Error:
			fmt.Println(err)
		case *exec.ExitError:
			fmt.Println("command exit rc =", e.ExitCode())
		default:
			panic(err)
		}
	}

	fmt.Println(string(cmdOut))
}

//check error as function
// run trivy in loop - separate files? report misses timestamp
