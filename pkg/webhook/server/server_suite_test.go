package server

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"

	"k8s.io/klog"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

func init() {
	klog.InitFlags(nil)
	logf.SetLogger(logf.ZapLogger(true))
}

func TestUnit(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.server_suite_test.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Server Test Suite", []Reporter{junitReporter})
}
