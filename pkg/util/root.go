package util

import (
	"os"
	"regexp"
)

func GetRootPath() string {
	projectDirName := os.Getenv("PROJECT_DIR_NAME")
	projectName := regexp.MustCompile(`^(.*` + projectDirName + `)`)
	currentWorkDirectory, _ := os.Getwd()
	return string(projectName.Find([]byte(currentWorkDirectory)))
}
