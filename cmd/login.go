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
	"fmt"
	"github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	clusterApi "github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"sigs.k8s.io/yaml"
)

var token string
var ak string
var sk string

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.
	loginCmd.PersistentFlags().StringVar(&token, "token", "", "Authentication Token for OTC")
	loginCmd.PersistentFlags().StringVar(&ak, "ak", "", "Access Key for OTC Authentication")
	loginCmd.PersistentFlags().StringVar(&sk, "sk", "", "Secret Key for OTC Authentication")
	//loginCmd.PersistentFlags().String("otc-login", "-v", "Get version of kubectl-otc-login")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func login(cmd *cobra.Command, args []string) {
	err := genClient()

	if err != nil {
		fmt.Println("Reason: ", err)
		os.Exit(1)
	}
}

func genClient() error {

	opts := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: "https://iam.eu-de.otc.t-systems.com/",
		ProjectId:        "cbfdd6db47e8447d8bc181cf9420194f",
		SecretKey:        sk,
		AccessKey:        ak,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return err
	}

	endOpts := golangsdk.EndpointOpts{
		Region: "eu-de",
	}

	cceServiceClient, err := openstack.NewCCE(provider, endOpts)
	if err != nil {
		return err
	}

	listOpts := clusterApi.ListOpts{}
	allClusters, err := clusterApi.List(cceServiceClient, listOpts) //TODO Fetch only one cluster not a whole list, user needs to provide clustername
	if err != nil {
		return err
	}

	singleCluster := allClusters[0]

	cert, err := clusterApi.GetCert(cceServiceClient, singleCluster.Metadata.Id).Extract()

	contextName := "OTC-123542-eu-de-pfau-infrastructure" //TODO replace me with ${TENANT-NAME}-${PROJECT-NAME}-${CLUSTER-NAME}
	userName := "ferhat"

	prepareKubectlConfig(cert, contextName, userName)

	y, err := yaml.Marshal(cert)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("/home/victor/test.yaml", y, 0777)
	if err != nil {
		return err
	}

	return nil
}

func prepareKubectlConfig(cert *clusterApi.Certificate, contextName string, userName string) {
	cert.Clusters = createCluster(cert.Clusters, contextName)
	cert.CurrentContext = contextName
	cert.Users = []clusterApi.CertUsers{{userName, cert.Users[0].User}}
	cert.Contexts = createContext(cert, contextName, userName)
}

func createContext(cert *clusterApi.Certificate, contextName string, userName string) []clusterApi.CertContexts {
	for _, v := range cert.Contexts {
		if v.Name == "external" {
			v.Name = contextName
			v.Context.User = userName
			v.Context.Cluster = contextName
			return []clusterApi.CertContexts{v}
		}
	}
	return nil
}

func createCluster(clusters []clusterApi.CertClusters, contextName string) []clusterApi.CertClusters {
	for _, v := range clusters {
		if v.Name == "externalCluster" {
			v.Name = contextName
			return []clusterApi.CertClusters{v}
		}
	}
	return nil
}
