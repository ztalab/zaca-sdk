package caclient

import (
	"log"

	"github.com/ztalab/zaca-sdk/pkg/logger"
	"go.uber.org/zap"
)

func init() {
	f := zap.RedirectStdLog(logger.S().Desugar())
	f()
	log.SetFlags(log.LstdFlags)
}
