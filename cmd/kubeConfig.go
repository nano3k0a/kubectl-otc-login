/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sigs.k8s.io/yaml"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/users"
	"github.com/spf13/cobra"
)

const (
	//https://docs.otc.t-systems.com/en-us/api/iam/iam_03_0002.html
	queryPAK = "https://iam.eu-de.otc.t-systems.com/v3.0/OS-CREDENTIAL/credentials/"

	//https://docs.otc.t-systems.com/en-us/api/iam/en-us_topic_0057845574.html
	queryDomain = "https://iam.eu-de.otc.t-systems.com/v3/auth/domains"
)

// kubeConfigCmd represents the kubeConfig command
var (
	ak          string
	sk          string
	path        string
	projectName string
	clusterName string

	kubeConfigCmd = &cobra.Command{
		Use:   "kubeConfig",
		Short: "kubecConfig downloads the kubectl configuration file from open telekom cloud (otc)",
		Long: `The kubectl configuration file with its ca, user certs and contexts is downloaded directly via the OTC API.
           After the kubectl config file is download it is modified so that only in the context for the external cluster
           exists. The kubectl config file will then be saved in the desired path (default is: $HOME/.kube/config)
           Examples: kubectl-otc-login fetch kubeConfig --sk yoursecretkey --ak youraccesskey --path /desired/path
           `,
		Run: main,
	}
)

func init() {
	//rootCmd.AddCommand(fetchCmd)
	fetchCmd.AddCommand(kubeConfigCmd)
	fetchCmd.PersistentFlags().StringVar(&ak, "ak", "", "Access Key for OTC Authentication")
	fetchCmd.PersistentFlags().StringVar(&sk, "sk", "", "Secret Key for OTC Authentication")
	fetchCmd.PersistentFlags().StringVar(&projectName, "projectName", "eu-de", "Project name from OTC console (default: eu-de)")
	fetchCmd.PersistentFlags().StringVar(&clusterName, "clusterName", "", "Name of the Cluster from OTC")
	fetchCmd.PersistentFlags().StringVar(&path, "path", "~/.kube/config", "Path where to save the config (default: ~/.kube/config")
}

func verifyParameters() {
	alphaNumeric := regexp.MustCompile("^[a-zA-Z0-9_]*$")

	if ak == "" || !alphaNumeric.MatchString(ak) {
		Error(errors.New("parameter access key (ak) not set or invalid"))
	}

	if sk == "" || !alphaNumeric.MatchString(ak) {
		Error(errors.New("parameter secret key (sk) not set or invalid"))
	}

	if projectName == "" {
		Error(errors.New("parameter projectName not set"))
	}

	if clusterName == "" {
		Error(errors.New("parameter clusterName not set"))
	}

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		Error(err)
	}
}

type KubeConfig struct {
	cceClient      *golangsdk.ServiceClient
	cceCluster     []clusters.Clusters
	kubeConfigCert *clusters.Certificate
	clusterName    string
	contextName    string
	userName       string
}

func NewKubeConfig() *KubeConfig {
	providerClient := getProviderClient()
	cceClient := getCCEClient()
	cluster := getCluster(cceClient)
	cert := getCert()
	contextName := getContextName(providerClient)
	userName := getUserName(providerClient)
	if userName == "" {
		Error(errors.New("No Username found for User_ID: " + cceClient.UserID))
	}

	return &KubeConfig{
		cceClient:      cceClient,
		cceCluster:     cluster,
		kubeConfigCert: cert,
		clusterName:    clusterName,
		contextName:    contextName,
		userName:       userName,
	}
}

func main(cmd *cobra.Command, args []string) {
	verifyParameters()
	cnf := NewKubeConfig()
	cnf.prepareKubectlConfig()
	cnf.writeKubeConfig()
}

func (k *KubeConfig) prepareKubectlConfig() {
	for _, v := range k.kubeConfigCert.Clusters {
		if v.Name == "externalCluster" {
			v.Name = k.contextName
			k.kubeConfigCert.Clusters = []clusters.CertClusters{v}
		}
	}

	k.kubeConfigCert.CurrentContext = k.contextName
	k.kubeConfigCert.Users = []clusters.CertUsers{{k.userName, k.kubeConfigCert.Users[0].User}}

	for _, v := range k.kubeConfigCert.Contexts {
		if v.Name == "external" {
			v.Name = k.contextName
			v.Context.User = k.userName
			v.Context.Cluster = k.contextName
			k.kubeConfigCert.Contexts = []clusters.CertContexts{v}
		}
	}
}

func (k *KubeConfig) writeKubeConfig() error {
	y, err := yaml.Marshal(k.kubeConfigCert)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, y, 0777)
	if err != nil {
		return err
	}
	return nil
}

func getProviderClient() *golangsdk.ProviderClient {
	opts := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: "https://iam.eu-de.otc.t-systems.com/",
		ProjectName:      projectName,
		SecretKey:        sk,
		AccessKey:        ak,
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		Error(err)
	}

	return provider
}

func getIdentityClient() *golangsdk.ServiceClient {

	opts := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: "https://iam.eu-de.otc.t-systems.com/",
		ProjectName:      projectName,
		Region:           "eu-de",
		SecretKey:        sk,
		AccessKey:        ak,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		Error(err)
	}
	endOpts := golangsdk.EndpointOpts{
		Region: "eu-de",
	}

	identityClient, err := openstack.NewIdentityV3(provider, endOpts)
	if err != nil {
		Error(err)
	}

	return identityClient
}

func getCCEClient() *golangsdk.ServiceClient {
	endOpts := golangsdk.EndpointOpts{
		Region: "eu-de",
	}

	cceServiceClient, err := openstack.NewCCE(getProviderClient(), endOpts)
	if err != nil {
		Error(err)
	}

	return cceServiceClient
}

func getCluster(cceClient *golangsdk.ServiceClient) []clusters.Clusters {
	listOpts := clusters.ListOpts{
		Name: clusterName,
	}

	singleCluster, err := clusters.List(cceClient, listOpts)
	if err != nil {
		Error(err)
	}

	if len(singleCluster) == 0 {
		Error(errors.New("cluster Slice is empty"))
	}
	return singleCluster
}

func getCert() *clusters.Certificate {
	cceClient := getCCEClient()
	cluster := getCluster(cceClient)
	var err error
	kubeConfigCert, err := clusters.GetCert(cceClient, cluster[0].Metadata.Id).Extract()
	if err != nil {
		Error(err)
	}

	return kubeConfigCert
}

type User struct {
	Credential struct {
		ID string `json:"user_id"`
	} `json:"credential"`
}

func getUserName(provider *golangsdk.ProviderClient) string {

	user := new(User)
	rOpts := &golangsdk.RequestOpts{
		JSONResponse: user,
		OkCodes:      []int{200},
	}
	resp, err := provider.Request("GET", queryPAK+ak, rOpts)
	if err != nil {
		Error(err)
	}

	//myUser := new(user)
	if resp.StatusCode == http.StatusOK {

	} else {
		Error(errors.New("GET request failed, status: " + resp.Status))
	}

	idClient := getIdentityClient()
	otcUser, err := users.Get(idClient, user.Credential.ID).Extract()
	if err != nil {
		Error(err)
	}

	return otcUser.Name
}

type Domain struct {
	Domains []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"domains"`
}

func getContextName(provider *golangsdk.ProviderClient) string {
	//"OTC-123542-eu-de-pfau-infrastructure"
	domain := new(Domain)
	opts := &golangsdk.RequestOpts{
		JSONResponse: domain,
		OkCodes:      []int{200},
	}
	resp, err := provider.Request("GET", queryDomain, opts)
	if err != nil {
		Error(err)
	}

	if resp.StatusCode != http.StatusOK {
		Error(errors.New("GET request failed, status: " + resp.Status))
	}

	if len(domain.Domains) == 0 {
		Error(errors.New("retrieved domain List is empty"))
	}

	return domain.Domains[0].Name + "-" + projectName + "-" + clusterName
}

// Error is a helper function to handle errors
func Error(e error) {
	fmt.Println(e)
	os.Exit(1)
}
