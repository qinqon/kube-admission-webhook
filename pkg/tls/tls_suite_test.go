package tls

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
)

func TestUnit(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.tls.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "TLS Security Profile Test Suite", []Reporter{junitReporter})
}
