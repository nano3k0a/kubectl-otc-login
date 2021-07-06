module main

go 1.16

replace (
	k8s.io/api => k8s.io/api v0.21.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.0
	k8s.io/client-go => k8s.io/client-go v0.21.0
)

require (
	github.com/gopherjs/gopherjs v0.0.0-20181103185306-d547d1d9531e // indirect
	github.com/opentelekomcloud/gophertelekomcloud v0.4.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.8.1
	k8s.io/client-go v0.21.2 // indirect
	sigs.k8s.io/yaml v1.2.0
)
