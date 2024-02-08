package utils

import (
	"fmt"
	"log"
)

// log message in log file.
func Logging(prefix string, message string, logger log.Logger) {
	prefix = fmt.Sprintf("%v :", prefix)
	logger.SetPrefix(prefix)
	logger.Println(message)
}
