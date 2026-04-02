package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/AsierCaballero/opa-policies/pkg/engine"
	"github.com/AsierCaballero/opa-policies/pkg/reporter"
)

var (
	policyDir string
	format    string
	namespace string
)

var rootCmd = &cobra.Command{
	Use:   "opa-policies",
	Short: "Policy-as-code validator for K8s, Terraform, Docker, and GitHub Actions",
}

var validateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a file against the policy library",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := engine.New(policyDir)
		if err != nil {
			return fmt.Errorf("engine init: %w", err)
		}

		results, err := e.ValidateFile(args[0])
		if err != nil {
			return err
		}

		var r reporter.Reporter
		switch format {
		case "table":
			r = &reporter.TableReporter{Out: os.Stdout}
		case "sarif":
			r = &reporter.SARIFReporter{Out: os.Stdout}
		case "junit":
			r = &reporter.JUnitReporter{Out: os.Stdout}
		default:
			r = &reporter.TableReporter{Out: os.Stdout}
		}

		return r.Report(results)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := engine.New(policyDir)
		if err != nil {
			return err
		}
		for _, p := range e.Policies() {
			fmt.Printf("  %s\n", p)
		}
		return nil
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run policy test suite",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := engine.New(policyDir)
		if err != nil {
			return err
		}
		return e.RunTests()
	},
}

func Execute() error {
	rootCmd.PersistentFlags().StringVarP(&policyDir, "policies", "p", "./policies", "policy directory")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "table", "output format (table, sarif, junit)")

	validateCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "policy namespace to filter by")

	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(testCmd)

	return rootCmd.Execute()
}
