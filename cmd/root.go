package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

type ConfigJson struct {
	ServerURI   string     `json:"server-uri"`
	Address     string     `json:"address"`
	DefaultUser string     `json:"default-user"`
	Base        string     `json:"base"`
	AdminDn     string     `json:"admin-dn"`
	Password    string     `json:"password"`
	Platform    string     `json:"platform"`
	Version     float64    `json:"version"`
	Roles       [][]string `json:"roles"`
}

var (
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use: "mlldap",
	Short: "Utility tool to check MarkLogic LDAP configurations" +
		".",
	Long: `
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Initialise all the argument flags and switches
func init() {
	cobra.OnInitialize(initConfig)

	cwd, err := os.Getwd()
	cfgPath := "."
	if err == nil {
		cfgPath = cwd
	}
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", cfgPath+"/config.json", "config file.")

	rootCmd.PersistentFlags().BoolP("debug", "", false, "Enable debugging.")
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	rootCmd.PersistentFlags().StringP("admin-dn", "d", "", "The Distinguished Name for the Service Security Admin role.")
	viper.BindPFlag("admin-dn", rootCmd.PersistentFlags().Lookup("admin-dn"))
	rootCmd.PersistentFlags().StringP("address", "a", "", "The comma-separated list of the IP addresses of your LDAP servers. Example: 192.0.2.235,198.51.100.234")
	viper.BindPFlag("address", rootCmd.PersistentFlags().Lookup("address"))
	rootCmd.PersistentFlags().StringP("server-uri", "s", "", "The URI of the LDAP server. Example: ldaps://ldap.mlaas.marklogic.com")
	viper.BindPFlag("server-uri", rootCmd.PersistentFlags().Lookup("server-uri"))
	rootCmd.PersistentFlags().StringP("base", "B", "", "The starting point for search. Example: DC=ldap,DC=mlaas,DC=marklogic,DC=com")
	viper.BindPFlag("base", rootCmd.PersistentFlags().Lookup("base"))
	rootCmd.PersistentFlags().StringP("default-user", "u", "", "The LDAP user to be used by MarkLogic. Example: CN=Admin,OU=Users,OU=ldap,DC=ldap,DC=mlaas,DC=marklogic,DC=com")
	viper.BindPFlag("default-user", rootCmd.PersistentFlags().Lookup("default-user"))
	rootCmd.PersistentFlags().StringP("password", "p", "", "The password for the LDAP default user account.")
	viper.BindPFlag("password", rootCmd.PersistentFlags().Lookup("password"))
	rootCmd.PersistentFlags().StringP("bind-method", "b", "simple", "Default is Simple. The LDAP default user must be a Distinguished Name (DN).")
	viper.BindPFlag("bind-method", rootCmd.PersistentFlags().Lookup("bind-method"))
	rootCmd.PersistentFlags().StringP("ldap-attribute", "A", "sAMAccountName", "The LDAP attribute for user lookup. The name of the attribute used to identify the user on the LDAP server. Default: sAMAccountName")
	viper.BindPFlag("ldap-attribute", rootCmd.PersistentFlags().Lookup("ldap-attribute"))
	rootCmd.PersistentFlags().StringP("memberof-attribute", "m", "memberOf", "The LDAP attribute for group lookup. Used to search for the groups of a user. Default: memberOf")
	viper.BindPFlag("memberof-attribute", rootCmd.PersistentFlags().Lookup("memberof-attribute"))
	rootCmd.PersistentFlags().StringP("member-attribute", "M", "member", "The LDAP attribute for group lookup. Used to search for the group of a group. Default: member")
	viper.BindPFlag("member-attribute", rootCmd.PersistentFlags().Lookup("member-attribute"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag or default
		viper.SetConfigFile(cfgFile)
	}

	// Default values
	viper.SetDefault("debug", false)
	viper.SetDefault("bind-method", "simple")
	viper.SetDefault("ldap-attribute", "sAMAccountName")
	viper.SetDefault("memberof-attribute", "memberOf")
	viper.SetDefault("member-attribute", "member")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		fmt.Println("Unable to read config file ", viper.ConfigFileUsed(), err)
	}

}
