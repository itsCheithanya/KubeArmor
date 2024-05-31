package ransomware

import (
	"fmt"
	// "strings"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// Configure privileged deployment
	// err := K8sApplyFile("policies/pod.yaml")
	// Expect(err).To(BeNil())
	
// Delete all KSPs
err := DeleteAllKsp()
Expect(err).To(BeNil())
})

// var _ = AfterSuite(func() {
// 	// Delete privileged deployment
// 	// err := K8sDelete([]string{"policies/pod.yaml"})
// 	// Expect(err).To(BeNil())
// })

func getPod(name string, namespace string, ant string) string {
	pods, err := K8sGetPods(name, namespace, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Ksp", func() {
	var privPod string

	BeforeEach(func() {
		privPod = getPod("privileged-pod", "default", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
	})

	Describe("Privileged Pod with nsenter Block Test", func() {
		It("should block nsenter command in privileged pod", func() {
			// Apply the KubeArmor policy to block nsenter
			err := K8sApply([]string{"policies/block-nsenter-in-privileged-pods.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "default", "Process", privPod)
			Expect(err).To(BeNil())

			// Execute nsenter inside the privileged pod - should be blocked
			sout, _, err := K8sExecInPodWithContainer(privPod, "default", "privileged-container",
				[]string{"nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp(".*Operation not permitted"))
	

			// Alert should be present for the above block
			expect := &protobuf.Alert{
				NamespaceName: "default",
				ContainerName: "privileged-container",
				PolicyName:    "block-nsenter-in-privileged-pods",
				Action:        "Block",
				Result:        "Use of nsenter is blocked in privileged containers",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeFalse())
		})
	})
})
