package chain

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"

	"k8s.io/klog"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log = logf.Log.WithName("certificate/chain_suite_test")
)

func init() {
	klog.InitFlags(nil)
}

func TestCertificate(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.chain_suite_test.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Reconciler Test Suite", []Reporter{junitReporter})
}
