/*
Copyright © 2024 Takahiro INAGAKI <inagaki0106@gmail.com>
*/
package cmd

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"

	"github.com/gomodule/redigo/redis"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// sessionViewCmd represents the sessionView command
var sessionViewCmd = &cobra.Command{
	Use:   "view",
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

		res, err := c.Do("get", "session_"+args[0])
		b, err := redis.Bytes(res, err)
		if err != nil {
			return err
		}

		var v map[any]any
		if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&v); err != nil {
			return err
		}

		vv := map[string]any{}
		for k, v := range v {
			vv[k.(string)] = v
		}
		j, err := json.MarshalIndent(vv, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(j))
		return nil
	},
}

func init() {
	sessionCmd.AddCommand(sessionViewCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sessionViewCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sessionViewCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
