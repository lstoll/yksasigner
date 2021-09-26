package main

import (
	"flag"
	"log"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	serviceaccountcontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

func main() {
	var (
		issuer     = flag.String("issuer", "", "OIDC issuer")
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig file, otherwise will use in-cluster config")
	)
	flag.Parse()

	var config *rest.Config
	if *kubeconfig != "" {
		c, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.Fatalf("Error flag config: %v", err)
		}
		config = c
	} else {
		c, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Error creating in cluster configuration: %v", err)
		}
		config = c
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	cards, err := piv.Cards()
	if err != nil {
		log.Fatalf("Error listing cards: %v", err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				log.Fatalf("Opening key")
			}
			break
		}
	}
	if yk == nil {
		log.Fatalf("No key found")
	}

	// TODO select slot
	s, err := newSigner(yk, piv.Slot{}, piv.DefaultPIN)
	if err != nil {
		log.Fatalf("Error creating signer: %v", err)
	}

	tg, err := serviceaccount.JWTTokenGenerator(*issuer, s)
	if err != nil {
		log.Fatalf("creating jwt token generator: %v", err)
	}

	factory := informers.NewSharedInformerFactory(cs, 0)

	controller, err := serviceaccountcontroller.NewTokensController(
		factory.Core().V1().ServiceAccounts(),
		factory.Core().V1().Secrets(),
		cs,
		serviceaccountcontroller.TokensControllerOptions{
			TokenGenerator: tg,
			// RootCA:         rootCA, // TODO?
		},
	)
	if err != nil {
		log.Fatalf("Error creating controller: %v", err)
	}

	// TODO - signal handle, shutdown, etc
	controller.Run(1, make(chan struct{}))
}
