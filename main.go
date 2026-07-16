package main

import (
	"encoding/json"
	"fmt"
	"os"

	"falcon/config"
	"falcon/core"
	"falcon/logger"
	"falcon/node"

	"github.com/spf13/cobra"
)

var (
	loglevel, nodes, N, T, nodeID                                                int
	path, keyFile, tssKeyFile, committeeFile, parametersFile, storePath, logPath string
)

func main() {
	var rootCmd = cobra.Command{
		Use:   "node",
		Short: "A research implementation of the Falcon asynchronous BFT consensus protocol.",
	}

	var keyCmd = cobra.Command{Use: "keys", Short: "Print fresh ed25519 key pairs to files"}
	keyCmd.Flags().StringVar(&path, "path", "", "The directory where to print the new key pairs")
	keyCmd.Flags().IntVar(&nodes, "nodes", 4, "The number of new key pairs")

	var tssKeyCmd = cobra.Command{Use: "threshold_keys", Short: "Print fresh threshold key shares to files"}
	tssKeyCmd.Flags().StringVar(&path, "path", "", "The directory where to print the new tss key shares")
	tssKeyCmd.Flags().IntVar(&N, "N", 4, "committee size")
	tssKeyCmd.Flags().IntVar(&T, "T", 2, "reconstruction threshold (f+1)")

	var runCmd = cobra.Command{Use: "run", Short: "Runs a single node"}
	runCmd.Flags().StringVar(&keyFile, "keys", "", "The file containing the node keys")
	runCmd.Flags().StringVar(&tssKeyFile, "threshold_keys", "", "The file containing the node threshold keys")
	runCmd.Flags().StringVar(&committeeFile, "committee", "", "The file containing committee information")
	runCmd.Flags().StringVar(&parametersFile, "parameters", "", "The file containing the node parameters")
	runCmd.Flags().StringVar(&storePath, "store", "", "The path where to create the data store")
	runCmd.Flags().StringVar(&logPath, "log_out", "", "The path where to write logs")
	runCmd.Flags().IntVar(&loglevel, "log_level", int(logger.DeployLevel), "The log verbosity level")
	runCmd.Flags().IntVar(&nodeID, "node_id", 0, "The ID of the node")

	var deployCmd = cobra.Command{Use: "deploy", Short: "Generates a local testbed and runs it in-process"}
	deployCmd.Flags().IntVar(&nodes, "nodes", 4, "The number of nodes to deploy")

	rootCmd.AddCommand(&keyCmd, &tssKeyCmd, &runCmd, &deployCmd)

	keyCmd.Run = func(cmd *cobra.Command, args []string) {
		config.GenerateKeyFiles(nodes, path)
	}

	tssKeyCmd.Run = func(cmd *cobra.Command, args []string) {
		config.GenerateTsKeyFiles(N, T, path)
	}

	runCmd.Run = func(cmd *cobra.Command, args []string) {
		n, err := node.NewNode(keyFile, tssKeyFile, committeeFile, parametersFile, storePath, logPath, loglevel, nodeID)
		if err != nil {
			logger.Error.Println(err)
			panic(err)
		}
		n.AnalyzeBlock()
	}

	deployCmd.Run = func(cmd *cobra.Command, args []string) {
		deploy(nodes)
	}

	if err := rootCmd.Execute(); err != nil {
		logger.Error.Println(err)
		panic(err)
	}
}

// deploy generates config/keys for `n` nodes and runs them all in this process.
func deploy(n int) {
	dir := "./.deploy"
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	// keys + threshold shares (threshold T = f+1)
	f := (n - 1) / 3
	config.GenerateKeyFiles(n, dir)
	config.GenerateTsKeyFiles(n, f+1, dir)

	// build committee from the generated public keys
	committee := core.Committee{Authorities: make(map[core.NodeID]core.Authority)}
	for i := 0; i < n; i++ {
		pub, _, err := config.GenKeysFromFile(fmt.Sprintf("%s/.node-key-%d.json", dir, i))
		if err != nil {
			panic(err)
		}
		committee.Authorities[core.NodeID(i)] = core.Authority{
			Name: pub,
			Id:   core.NodeID(i),
			Addr: fmt.Sprintf("127.0.0.1:%d", config.DefaultPort+i),
		}
	}
	committeeFile := fmt.Sprintf("%s/.committee.json", dir)
	config.WriteCommittee(committee, committeeFile)

	// parameters
	paramsFile := fmt.Sprintf("%s/.parameters.json", dir)
	writeParameters(paramsFile)

	logger.SetLevel(logger.TestLevel)
	for i := 0; i < n; i++ {
		go func(i int) {
			storeP := fmt.Sprintf("%s/.store-%d", dir, i)
			_ = os.RemoveAll(storeP)
			nd, err := node.NewNode(
				fmt.Sprintf("%s/.node-key-%d.json", dir, i),
				fmt.Sprintf("%s/.node-ts-key-%d.json", dir, i),
				committeeFile,
				paramsFile,
				storeP,
				"", // log to stdout
				int(logger.TestLevel),
				i,
			)
			if err != nil {
				panic(err)
			}
			nd.AnalyzeBlock()
		}(i)
	}

	select {} // block forever
}

func writeParameters(filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	if err := enc.Encode(config.GenDefaultParameters()); err != nil {
		panic(err)
	}
}
