/*
Copyright © 2022 SUSE LLC

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
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "host-resolver",
		Short: "Rancher Desktop DNS resolver",
		Long: `This stub resolver handles the DNS resolution on the host machine,
it allows for more robust name resolution in split VPN tunneling scenarios.
It can run on Windows, Darwin and Linux.`,
		Args: cobra.MinimumNArgs(1),
		Run:  func(cmd *cobra.Command, args []string) {},
	}
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
