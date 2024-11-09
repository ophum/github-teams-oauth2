/*
Copyright © 2024 Takahiro INAGAKI <inagaki0106@gmail.com>
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/gomodule/redigo/redis"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// sessionListCmd represents the sessionList command
var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return viper.Unmarshal(&conf)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := redis.Dial("tcp", fmt.Sprintf("%s:%d", conf.Session.Redis.Address, conf.Session.Redis.Port))
		if err != nil {
			return err
		}
		defer c.Close()

		res, err := c.Do("keys", "session_*")
		b, err := redis.ByteSlices(res, err)
		if err != nil {
			return err
		}

		for _, bb := range b {
			fmt.Println(strings.TrimLeft(string(bb), "session_"))
		}
		return nil
	},
}

func init() {
	sessionCmd.AddCommand(sessionListCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sessionListCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sessionListCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
