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
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/users"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	//"encoding/json"
	"os"
	"sigs.k8s.io/yaml"
)

var ak string
var sk string
var path string
var projectname string
var clustername string

// kubeConfigCmd represents the kubeConfig command
var kubeConfigCmd = &cobra.Command{
	Use:   "kubeConfig",
	Short: "kubecConfig downloads the kubectl configuration file from open telekom cloud (otc)",
	Long: `The kubectl configuration file with its ca, user certs and contexts is downloaded directly via the OTC API.
           After the kubectl config file is download it is modified so that only in the context for the external cluster
           exists. The kubectl config file will then be saved in the desired path (default is: $HOME/.kube/config)
           Examples: kubectl-otc-login fetch kubeConfig --sk yoursecretkey --ak youraccesskey --path /desired/path
           `,
	Run: main,
}

func init() {
	//rootCmd.AddCommand(fetchCmd)
	fetchCmd.AddCommand(kubeConfigCmd)
	fetchCmd.PersistentFlags().StringVar(&ak, "ak", "", "Access Key for OTC Authentication")
	fetchCmd.PersistentFlags().StringVar(&sk, "sk", "", "Secret Key for OTC Authentication")
	fetchCmd.PersistentFlags().StringVar(&projectname, "projectname", "eu-de", "Project name from OTC console")
	fetchCmd.PersistentFlags().StringVar(&clustername, "clustername", "", "Name of the Cluster from OTC")
	fetchCmd.PersistentFlags().StringVar(&path, "path", "~/.kube/config", "Path where to save the config (default: ~/.kube/config")
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
	cluster := getCluster(clustername, cceClient)
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
		clusterName:    clustername,
		contextName:    contextName,
		userName:       userName,
	}
}

func main(cmd *cobra.Command, args []string) {
	cnf := NewKubeConfig()
	cnf.prepareKubectlConfig()
	cnf.writeKubeConfig()
	getSAMLIdentity()

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
		ProjectName:      projectname,
		SecretKey:        sk,
		AccessKey:        ak,
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		Error(err)
	}

	return provider
}

func getSAMLIdentity() {
	res, err := http.Get("https://auth-pfau.telekom.de/auth/realms/mbfd/protocol/saml/descriptor")
	if err != nil {
		panic(err)
	}

	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	type EntitiesDescriptor struct {
		EntityDescriptor struct {
			*types.EntityDescriptor
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	}

	metadata := &EntitiesDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}
	//randomKeyStore := dsig.RandomKeyStoreForTest()
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityDescriptor.EntityID,
		ServiceProviderIssuer:       "https://auth.otc.t-systems.com",
		AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
		AudienceURI:                 "https://auth.otc.t-systems.com",
		IDPCertificateStore:         &certStore,
		NameIdFormat:                "email",
		//SPKeyStore:                  randomKeyStore,
	}

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		assertionInfo, err := sp.RetrieveAssertionInfo(req.FormValue("SAMLResponse"))
		if err != nil {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.InvalidTime {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.NotInAudience {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Fprintf(rw, "NameID: %s\n", assertionInfo.NameID)

		fmt.Fprintf(rw, "Assertions:\n")

		for key, val := range assertionInfo.Values {
			fmt.Fprintf(rw, "  %s: %+v\n", key, val)
		}

		fmt.Fprintf(rw, "\n")

		fmt.Fprintf(rw, "Warnings:\n")
		fmt.Fprintf(rw, "%+v\n", assertionInfo.WarningInfo)
	})

	println("Visit this URL To Authenticate:")
	authURL, err := sp.BuildAuthURL("")
	if err != nil {
		panic(err)
	}

	println(authURL)

	println("Supply:")
	fmt.Printf("SP ACS URL: %s\n", sp.AssertionConsumerServiceURL)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}

	if err != nil {
		Error(err)
	}
}

func getIdentityClient() *golangsdk.ServiceClient {

	opts := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: "https://iam.eu-de.otc.t-systems.com/",
		ProjectName:      projectname,
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

func getCluster(clusterName string, cceClient *golangsdk.ServiceClient) []clusters.Clusters {
	listOpts := clusters.ListOpts{
		Name: clusterName,
	}
	singleCluster, err := clusters.List(cceClient, listOpts) //TODO Fetch only one cluster not a whole list, user needs to provide clustername
	if err != nil {
		Error(err)
	}

	if len(singleCluster) == 0 {
		Error(errors.New("Cluster Slice is empty!"))
	}
	return singleCluster
}

func getCert() *clusters.Certificate {
	cceClient := getCCEClient()
	cluster := getCluster(clustername, cceClient)
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
	resp, err := provider.Request("GET", "https://iam.eu-de.otc.t-systems.com/v3.0/OS-CREDENTIAL/credentials/"+ak, rOpts)
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
	resp, err := provider.Request("GET", "https://iam.eu-de.otc.t-systems.com/v3/auth/domains", opts)
	if err != nil {
		Error(err)
	}
	if resp.StatusCode != http.StatusOK {
		Error(errors.New("GET request failed, status: " + resp.Status))
	}

	if len(domain.Domains) == 0 {
		Error(errors.New("Retrieve domain List is empty"))
	}

	return domain.Domains[0].Name + "-" + projectname + "-" + clustername
}

//Helper functions

func Error(e error) {
	fmt.Println(e)
	os.Exit(1)
}