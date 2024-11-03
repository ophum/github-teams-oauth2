/*
Copyright © 2024 Takahiro INAGAKI <inagaki0106@gmail.com>
*/
package cmd

import (
	"context"

	"github.com/ophum/github-teams-oauth2/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.Unmarshal(&conf); err != nil {
			return err
		}
		db, err := conf.Database.Open()
		if err != nil {
			return err
		}
		defer db.Close()

		if err := db.Schema.Create(context.Background()); err != nil {
			return err
		}
		return nil

	},
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := server.New(&conf)
		if err != nil {
			return err
		}
		defer s.Shutdown()
		return s.Run()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
