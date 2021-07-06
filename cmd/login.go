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
	"io/ioutil"
	"k8s.io/kops/pkg/kubeconfig"

	//"github.com/ghodss/yaml"
	"github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
	"github.com/spf13/cobra"

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

	listOpts := clusters.ListOpts{}
	allClusters, err := clusters.List(cceServiceClient, listOpts)
	if err != nil {
		return err
	}

	singleCluster := allClusters[0]

	//fmt.Printf("%v\n", allClusters[0])
	/*
		for _, cluster := range allClusters {
			fmt.Printf("%v\n", cluster)
		}
	*/
	kubectlCluster := kubeconfig.KubectlCluster{}
	kubectlUser := kubeconfig.KubectlUser{}
	kubectlContext := kubeconfig.KubectlContext{}
	cert, err := clusters.GetCert(cceServiceClient, singleCluster.Metadata.Id).Extract()

	for k, v := range cert.Clusters {
		if v.Name == "externalCluster" {
			kubectlCluster.Server = v.Cluster.Server
			kubectlCluster.CertificateAuthorityData = []byte(v.Cluster.CertAuthorityData)
			kubectlUser.ClientKeyData = []byte(cert.Users[k-1].User.ClientKeyData)
			kubectlUser.ClientCertificateData = []byte(cert.Users[k-1].User.ClientCertData)
			kubectlUser.Username = cert.Users[k-1].Name
			kubectlContext.Cluster = cert.CurrentContext
			kubectlContext.User = cert.Contexts[k-1].Context.User
		}
	}
	config := &kubeconfig.KubectlConfig{
		ApiVersion: cert.ApiVersion,
		Kind:       cert.Kind,
		Users: []*kubeconfig.KubectlUserWithName{
			{
				Name: kubectlUser.Username,
				User: kubectlUser,
			},
		},
		Clusters: []*kubeconfig.KubectlClusterWithName{
			{
				Name:    kubectlCluster.Server,
				Cluster: kubectlCluster,
			},
		},
		Contexts: []*kubeconfig.KubectlContextWithName{
			{
				Name: kubectlContext.Cluster,
				Context: kubeconfig.KubectlContext{
					Cluster: kubectlContext.Cluster,
					User:    kubectlContext.User,
				},
			},
		},
		CurrentContext: cert.CurrentContext,
	}

	//cnf, err := clientcmd.LoadFromFile("/home/ferhat/.kube/config")
	if err != nil {
		return err
	}
	cert.Clusters[0].Name = allClusters[0].Metadata.Name

	y, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("/home/ferhat/test.yaml", y, 0777)
	if err != nil {
		return err
	}

	/*
		user := kubeconfig.KubectlUser {
			ClientCertificateData: cert.Users[0].User.ClientCertData,
			ClientKeyData:         cert.Users[0].User.ClientKeyData,
		}
		cluster := kubeconfig.KubectlCluster{
			CertificateAuthorityData: cert.Clusters[0].Cluster.CertAuthorityData,
			Server:                   cert.Clusters[0].Cluster.Server,
		}

		myKubeConfig := &kubeconfig.KubectlConfig{
			Kind:           allClusters[0].Kind,
			ApiVersion:     allClusters[0].ApiVersion,
			CurrentContext: cert.CurrentContext,
			Clusters:       []*kubeconfig.KubectlClusterWithName{
				{
					Name:    "local",
					Cluster: cluster,
				},
			},
			Contexts:       []*kubeconfig.KubectlContextWithName{
				{
					Name: "service-account-context",
					Context: kubeconfig.KubectlContext{
						Cluster: allClusters[0].Metadata.Name,
						User:    cert.Contexts[0].Name,
					},
				},
			},
			Users:          []*kubeconfig.KubectlUserWithName{
				{
					Name: cert.Users[0].Name,
					User: user,
				},
			},
		}


		yaml, err := yaml.Marshal(myKubeConfig)
		if err != nil {
			return fmt.Errorf("error marshaling kubeconfig to yaml: %v", err)
		}
		err = ioutil.WriteFile("test.yaml",yaml,0777)
		if err != nil {
			return err
		}


		/*
		y, err := yaml.Marshal(cert)
		if err != nil {
			return err
		}

		var clusters map[string]*clientcmdapi.Cluster
		clusters["name"] = cert

		kconf := clientcmdapi.NewConfig()
		kconf.Kind = allClusters[0].Kind
		kconf.Clusters = clusters

		cnf, _ := clientcmd.Load(y)
		//cnf, _ := clientcmd.RESTConfigFromKubeConfig(y)
		//kubeconfig, _ := clientcmd.BuildConfigFromKubeconfigGetter(cnf)


		err = clientcmd.WriteToFile(*cnf, "/home/ferhat/test.yaml")
		if err != nil{
			return err
		}
	*/
	return nil
}
