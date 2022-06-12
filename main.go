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
var scanDirName string

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
		fmt.Printf("Project found, webUrl: %s \n", projects[i].WebURL)
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
	var allImages []string
	var uniqueImages []string
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

			// Store all images as flat slice and remove duplicates
			allImages = append(allImages, imageName)
			uniqueImages = unique(allImages)
		}

		defer resp.Body.Close()
	}

	fmt.Println("")

	// Save detected images per project to file
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

	fmt.Println("")
	fmt.Printf("Image list saved to ./%s \n", imageListFileName)
	fmt.Println("")

	// Run Trivy
	if *trivy {
		// Prepare scans directory
		//os.RemoveAll("scans")
		scanDirName = "scans-" + currentTimeStamp
		err := os.Mkdir(scanDirName, 0755)
		check(err)

		fmt.Println("Running Trivy scans...")
		fmt.Println("")
		for _, image := range uniqueImages {
			runTrivy(image)
		}

		fmt.Println("Trivy scans saved to scans-* directory. Empty scan results and failed scans have been removed.")

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

func unique(inputSlice []string) []string {
	keys := make(map[string]bool)
	uniqueSlice := []string{}

	for _, entry := range inputSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			uniqueSlice = append(uniqueSlice, entry)
		}
	}
	return uniqueSlice
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

func runTrivy(image string) {
	fmt.Printf("\u21BB Scanning %s...\n", image)
	fmt.Println("")
	scanFilePath := scanDirName + "/scan-" + currentTimeStamp + "-" + image
	args := []string{"image", "-s", "HIGH,CRITICAL", "-f", "table", "-o", scanFilePath, image}
	cmd := exec.Command("trivy", args...)

	cmdOut, err := cmd.Output()
	if err != nil {
		fmt.Printf("Unable not scan image: %s\n", image)
	}

	fmt.Println(string(cmdOut))

	// Delete empty files (failed scans or empty results)
	fi, err := os.Stat(scanFilePath)
	check(err)
	if fi.Size() == 0 {
		err := os.Remove(scanFilePath)
		check(err)
	}

}

// check error as function
