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
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/users"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"io"
	"net/url"
	"strings"

	"github.com/russellhaering/gosaml2"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
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
	getSAMLIdentityIDP()

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

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return createSAMLRequestLink(req)
		},
	}

	client.Get("https://auth.otc.t-systems.com/authui/federation/websso?domain_id=a2e751a00b42478eaeee3588b9e02dd5&idp=otc&protocol=saml")

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		samlResponseXML := replaceSAMLCallbackUrl(req, "http://localhost:8080/v1/_saml_callback", "https://iam.eu-de.otc.t-systems.com/v3-ext/auth/OS-FEDERATION/SSO/SAML2/POST", false)
		body := "SAMLResponse=" + samlResponseXML

		req2, err := http.NewRequest("POST", "https://iam.eu-de.otc.t-systems.com/v3.0/OS-FEDERATION/tokens", strings.NewReader(body))
		if err != nil {
			Error(err)
		}
		req2.Header.Set("x-Idp-Id", "otc")
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post, err := client.Do(req2)

		test, _ := ioutil.ReadAll(post.Body)
		println(string(test))
	})

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		Error(err)
	}

}

func getSAMLIdentityIDP() {
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
		NameIdFormat:                "transient",
	}

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		samlResponseXML := replaceSAMLCallbackUrl(req, "http://localhost:8080/v1/_saml_callback", "https://iam.eu-de.otc.t-systems.com/v3-ext/auth/OS-FEDERATION/SSO/SAML2/POST", false)
		body := "SAMLResponse=" + samlResponseXML

		req2, err := http.NewRequest("POST", "https://iam.eu-de.otc.t-systems.com/v3.0/OS-FEDERATION/tokens", strings.NewReader(body))
		if err != nil {
			Error(err)
		}
		req2.Header.Set("x-Idp-Id", "otc")
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{}
		post, err := client.Do(req2)

		test, _ := ioutil.ReadAll(post.Body)
		println(string(test))
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

func replaceSAMLCallbackUrl(req *http.Request, oldSAMLUrl, newSAMLUrl string, compress bool) string {
	err := req.ParseForm()
	if err != nil {
		Error(err)
	}
	samlResponse := req.FormValue("SAMLResponse")
	reqBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		Error(err)
	}
	samlResponse = string(reqBytes)
	samlResponseXML := strings.ReplaceAll(samlResponse, oldSAMLUrl, newSAMLUrl)
	//regex := regexp.MustCompile("InResponseTo=\"[-\\w]+\"")
	//result := regex.ReplaceAllString(samlResponseXML, "")
	return url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(samlResponseXML)))
}

func createSAMLRequestLink(req *http.Request) error {
	println("Visit this URL To Authenticate:")
	samlRequest := req.URL.Query().Get("SAMLRequest")

	reqBytes, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		Error(err)
	}

	buf := new(bytes.Buffer)

	decompressor := flate.NewReader(bytes.NewReader(reqBytes))
	io.Copy(buf, decompressor)
	decompressor.Close()
	samlResponseXML := string(buf.Bytes())
	samlResponseXML = strings.Replace(samlResponseXML, "https://auth.otc.t-systems.com/authui/saml/SAMLAssertionConsumer", "http://localhost:8080/v1/_saml_callback", -1)
	//fmt.Println(samlResponseXML)
	buf.Reset()

	compressor, _ := flate.NewWriter(buf, flate.BestCompression)
	defer compressor.Close()
	compressor.Write([]byte(samlResponseXML))
	compressor.Flush()
	samlResponseXML = base64.StdEncoding.EncodeToString(buf.Bytes())

	fmt.Print("\nVisit this URL:")

	req.URL.Query().Set("SAMLRequest", samlResponseXML)
	u, _ := url.ParseQuery(req.URL.RawQuery)
	u.Set("SAMLRequest", samlResponseXML)
	req.URL.RawQuery = u.Encode()
	println("https://" + req.URL.Host + req.URL.EscapedPath() + "?" + req.URL.RawQuery)
	//fmt.Println(req.URL.Query().Get("SAMLRequest"))
	return http.ErrUseLastResponse
}

type loggingResponseWriter struct {
	status int
	body   string
	http.ResponseWriter
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(body []byte) (int, error) {
	w.body = string(body)
	return w.ResponseWriter.Write(body)
}

func responseLogger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggingRW := &loggingResponseWriter{
			ResponseWriter: w,
		}
		h.ServeHTTP(loggingRW, r)
		log.Println("Status : ", loggingRW.status, "Response : ", loggingRW.body)
	})
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
