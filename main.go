package main

import (
	"flag"
	"fmt"
	"time"
	"github.com/golang/glog"
	csrclient "k8s.io/client-go/util/certificate/csr"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	mapiclient "github.com/openshift/cluster-api/pkg/client/clientset_generated/clientset"
)

const machineAPINamespace = "openshift-machine-api"

type Controller struct {
	clientset	*kubernetes.Clientset
	machineClient	*mapiclient.Clientset
	indexer		cache.Indexer
	queue		workqueue.RateLimitingInterface
	informer	cache.Controller
}

func NewController(clientset *kubernetes.Clientset, machineClientset *mapiclient.Clientset, queue workqueue.RateLimitingInterface, indexer cache.Indexer, informer cache.Controller) *Controller {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &Controller{clientset: clientset, machineClient: machineClientset, informer: informer, indexer: indexer, queue: queue}
}
func (c *Controller) processNextItem() bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.handleNewCSR(key.(string))
	c.handleErr(err, key)
	return true
}
func (c *Controller) handleNewCSR(key string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	obj, exists, err := c.indexer.GetByKey(key)
	if err != nil {
		glog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}
	if !exists {
		glog.Infof("CSR %s does not exist anymore\n", key)
		return nil
	}
	csr := obj.(*certificatesv1beta1.CertificateSigningRequest).DeepCopy()
	glog.Infof("CSR %s added\n", csr.GetName())
	var alreadyApproved bool
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1beta1.CertificateApproved {
			alreadyApproved = true
			break
		}
	}
	if alreadyApproved {
		glog.Infof("CSR %s is already approved\n", csr.GetName())
		return nil
	}
	parsedCSR, err := csrclient.ParseCSR(csr)
	if err != nil {
		glog.Infof("error parsing request CSR: %v", err)
		return nil
	}
	approvalMsg := "This CSR was approved by the Node CSR Approver"
	machineList, err := c.machineClient.MachineV1beta1().Machines(machineAPINamespace).List(metav1.ListOptions{})
	if err == nil {
		err := authorizeCSR(machineList, csr, parsedCSR)
		if err != nil {
			glog.Infof("CSR %s not authorized: %v", csr.GetName(), err)
			return nil
		}
	}
	if err != nil {
		glog.Infof("machine api not available: %v", err)
		_, err := validateCSRContents(csr, parsedCSR)
		if err != nil {
			glog.Infof("CSR %s not valid: %v", csr.GetName(), err)
			return nil
		}
		approvalMsg += " (no SAN validation)"
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1beta1.CertificateSigningRequestCondition{Type: certificatesv1beta1.CertificateApproved, Reason: "NodeCSRApprove", Message: approvalMsg, LastUpdateTime: metav1.Now()})
	if _, err := c.clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr); err != nil {
		return err
	}
	glog.Infof("CSR %s approved\n", csr.GetName())
	return nil
}
func (c *Controller) handleErr(err error, key interface{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if err == nil {
		c.queue.Forget(key)
		return
	}
	if c.queue.NumRequeues(key) < 5 {
		glog.Infof("Error syncing csr %v: %v", key, err)
		c.queue.AddRateLimited(key)
		return
	}
	c.queue.Forget(key)
	utilruntime.HandleError(err)
	glog.Infof("Dropping CSR %q out of the queue: %v", key, err)
}
func (c *Controller) Run(threadiness int, stopCh chan struct{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()
	glog.Info("Starting Machine Approver")
	go c.informer.Run(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}
	<-stopCh
}
func (c *Controller) runWorker() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	for c.processNextItem() {
	}
}
func main() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var kubeconfig string
	var master string
	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		glog.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatal(err)
	}
	machineClient, err := mapiclient.NewForConfig(config)
	if err != nil {
		glog.Fatal(err)
	}
	csrListWatcher := cache.NewListWatchFromClient(client.CertificatesV1beta1().RESTClient(), "certificatesigningrequests", v1.NamespaceAll, fields.Everything())
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	indexer, informer := cache.NewIndexerInformer(csrListWatcher, &certificatesv1beta1.CertificateSigningRequest{}, 0, cache.ResourceEventHandlerFuncs{AddFunc: func(obj interface{}) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err == nil {
			queue.Add(key)
		}
	}}, cache.Indexers{})
	controller := NewController(client, machineClient, queue, indexer, informer)
	stop := make(chan struct{})
	defer close(stop)
	go controller.Run(1, stop)
	select {}
}
