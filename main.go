package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/lon9/inco"
)

func main() {

	u := os.Getenv("TRIVY_NOTIFY_WEBHOOK_URL")
	sev := os.Getenv("TRIVY_NOTIFY_SEVERITY")
	confPath := os.Getenv("TRIVY_NOTIFY_CONF_PATH")
	templatePath := os.Getenv("TRIVY_NOTIFY_TEMPLATE_PATH")

	content, err := ioutil.ReadFile(confPath)
	if err != nil {
		panic(err)
	}
	repos := strings.Split(string(bytes.TrimSpace(content)), "\n")
	if err := exec.Command("trivy", "image", "--clear-cache").Run(); err != nil {
		panic(err)
	}

	for _, repo := range repos {
		log.Printf("Scanning %s\n", repo)
		out, err := exec.Command(
			"trivy",
			"image",
			"--no-progress",
			"--severity",
			sev,
			"--format",
			"template",
			"--template",
			"@"+templatePath,
			repo).
			Output()
		if err != nil {
			log.Println(err)
			continue
		}
		txt := fmt.Sprintf("```Image: %s\n%s```", repo, bytes.SplitN(out, []byte("\n\n"), 2)[1])
		msg := inco.Message{
			Text: txt,
		}
		if len(txt) > 2000 {
			msg.Text = fmt.Sprintf("```Image: %s has so many vulnerabilities```", repo)
		}
		if err := inco.Incoming(u, &msg); err != nil {
			log.Println(err)
			continue
		}
	}
}
