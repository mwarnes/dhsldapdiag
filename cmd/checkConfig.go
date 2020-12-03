package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/cloverstd/tcping/ping"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-ldap/ldap/v3"
	"github.com/gookit/color"
	"github.com/inancgumus/screen"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type roleStruct struct {
	rolename   string
	externalDN []string
}

var roles []roleStruct
var accountuid string
var accountdn string
var accountpword string
var verified bool

//var logmsg color.Style
var logmsg color.RGBColor

var checkConfig = &cobra.Command{
	Use:   "checkconfig",
	Short: "Verify an LDAP connection",
	Long: `Verify the connection and LDAP settings prior to configuring DHS External Security."

Examples:

checkconfig 

`,
	Run: func(cmd *cobra.Command, args []string) {
		checkLdapConfiguration()
	},
}

func init() {
	rootCmd.AddCommand(checkConfig)

}

func checkLdapConfiguration() {
	//logmsg = color.New(color.FgBlue, color.OpBold)
	logmsg = color.HEX("#1976D2")
	if viper.GetBool("debug") {
		log.Println(spew.Sdump(viper.AllSettings()))
	}

	// Check that we have all the required parameters and prompt for any missing values
	admindn := validateField("admin-dn", false)
	address := validateField("address", false)
	serveruri := validateField("server-uri", false)
	base := validateField("base", false)
	defaultuser := validateField("default-user", false)
	bindmethod := validateField("bind-method", false)
	ldapattribute := validateField("ldap-attribute", false)
	memberofattribute := validateField("memberof-attribute", false)
	memberattribute := validateField("member-attribute", false)
	password := validateField("default-user password", true)

	// Display chosen values and prompt to continue
	screen.Clear()
	screen.MoveTopLeft()
	banner("DHS LDAP Verification")
	data := [][]string{
		[]string{"Security Admin DN", admindn},
		[]string{"DNS Address", address},
		[]string{"Server URI", serveruri},
		[]string{"Base", base},
		[]string{"Default User", defaultuser},
		[]string{"Bind Method", bindmethod},
		[]string{"LDAP Attribute", ldapattribute},
		[]string{"MemberOf Attribute", memberofattribute},
		[]string{"Member Attribute", memberattribute},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"LDAP Field", "Value"})
	table.SetColMinWidth(1, 80)
	table.SetAutoWrapText(false)
	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})
	for _, v := range data {
		table.Append(v)
	}
	table.Render()

	dat, _ := ioutil.ReadFile(viper.ConfigFileUsed())
	var configJson ConfigJson
	err := json.Unmarshal(dat, &configJson)
	if err != nil {
		log.Println(err)
	}

	table = tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Role", "External DN"})
	table.SetColMinWidth(1, 80)
	table.SetAutoWrapText(false)
	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})
	for _, role := range configJson.Roles {
		var extdn string
		for i := 1; i < len(role); i++ {
			extdn = extdn + role[i] + "\n"
		}
		table.Append([]string{role[0], extdn})
	}
	table.Render()

	promptContinue(color.Question.Sprintf("Continue"), "Y")

	// Determine LDAP protocol
	u, err := url.Parse(serveruri)
	if err != nil {
		log.Println(serveruri, " is not a valid uri.")
		log.Println(err)
		os.Exit(0)
	}
	scheme := u.Scheme
	isLdapSecure := false
	switch strings.ToUpper(scheme) {
	case "LDAPS":
		isLdapSecure = true
	case "LDAP":
		isLdapSecure = false
	default:
		log.Println("URI scheme must be either LDAP or LDAPS.")
		os.Exit(0)
	}

	host := u.Host
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		if isLdapSecure {
			port = "636"
		} else {
			port = "389"
		}
	}
	hostname := u.Hostname()

	success, failures := checkConnectivity(address, hostname, port)
	if success == 0 {
		color.Error.Println("Unable to connect to any LDAP Servers.")
		os.Exit(0)
	}
	if failures > 0 {
		if failures == 0 {
			promptContinue(color.Success.Sprintf("%d Failures reported during connectivity test, do you want to continue.", failures), "N")
		} else {
			promptContinue(color.Danger.Sprintf("%d Failures reported during connectivity test, do you want to continue.", failures), "N")
		}
	} else {
		promptContinue(color.Question.Sprintf("Continue to check LDAP Default User bind"), "Y")
	}

	conn := checkLdapAdminBind(hostname, port, isLdapSecure, bindmethod, defaultuser, password)
	defaultUserConn := conn

	adminaccounts := checkAdminDN(conn, admindn, base, memberofattribute, ldapattribute)

	verified = verifyAdminAccount(hostname, port, isLdapSecure, bindmethod, adminaccounts)

	checkRolesDN(defaultUserConn, configJson, base, memberofattribute, ldapattribute)
	generateRolesRequests("curl")

}

func generateRolesRequests(format string) {
	banner("Generating Role Mapping Requests")
	//TODO Handle different command formats but for now it's just curl

	//curl -X POST --anyauth -u USERNAME:PASSWORD -H "Content-Type:application/json" \
	//-d '{"role-name": "custom-pii-reader","role": ["pii-reader"],"external-names":[{"external-name":"ROLE_DN"}]}' \
	//https://DHS_ENDPOINT:8003/manage/v2/roles/

	for _, role := range roles {
		var sb strings.Builder
		var eb strings.Builder
		sb.WriteString("curl -k -X POST --anyauth")
		if verified {
			sb.WriteString(" -u ")
			sb.WriteString(accountuid)
			sb.WriteString(":")
			sb.WriteString(accountpword)
		} else {
			sb.WriteString(" -u ")
			sb.WriteString("USERID")
			sb.WriteString(":")
			sb.WriteString("PASSWORD")
		}
		sb.WriteString(" -H \"Content-Type:application/json\" ")
		sb.WriteString("-d '{\"role-name\":")
		sb.WriteString("\"")
		sb.WriteString(role.rolename)
		sb.WriteString("\",\"role\": [\"")
		sb.WriteString(strings.Trim(role.rolename, "custom-"))
		sb.WriteString("\"],\"external-names\":[")
		for _, dn := range role.externalDN {
			eb.WriteString("{\"external-name\":\"")
			eb.WriteString(dn)
			eb.WriteString("\"},")
		}
		sb.WriteString(strings.TrimSuffix(eb.String(), ","))
		sb.WriteString("]}' https://DHS_ENDPOINT:8003/manage/v2/roles/")
		println(sb.String())
	}

}

func verifyAdminAccount(hostname string, port string, secure bool, bindmethod string, adminaccounts [][]string) bool {
	//color.Success.Println("Verifying Security Admin account access (optional)")
	banner("Verifying Security Admin account access (optional)")
	net.JoinHostPort(hostname, port)
	var conn *ldap.Conn
	var err error
	var config *tls.Config
	if secure {
		config = &tls.Config{}
		config.InsecureSkipVerify = true
		logmsg.Println("Establishing secure connection to LDAP server.")
		conn, err = ldap.DialTLS("tcp", net.JoinHostPort(hostname, port), config)
		if viper.GetBool("debug") {
			log.Println(spew.Sdump(conn.TLSConnectionState()))
			conn.Debug.Enable(true)
		}
	} else {
		logmsg.Println("Establishing connection to LDAP server.")
		conn, err = ldap.Dial("tcp", net.JoinHostPort(hostname, port))
		if viper.GetBool("debug") {
			conn.Debug.Enable(true)
		}
	}
	if err != nil {
		color.Error.Printf("Failed to connect to LDAP Server. %s", err)
		os.Exit(0)
	}

	var accounts []string
	for _, account := range adminaccounts {
		accounts = append(accounts, account[0])
	}
	accounts = append(accounts, ">>Skip<<")

	sprompt := promptui.Select{
		Label: logmsg.Sprintf("Select Security Account to verify"),
		Items: accounts,
	}

	_, account, err := sprompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return false
	}

	if account == ">>Skip<<" {
		return false
	}

	for _, a := range adminaccounts {
		if a[0] == account {
			accountdn = a[1]
			accountuid = a[0]
			break
		}
	}

	//TODO Convert to a loop to allow for errors
	var retval bool
	for {
		prompt := promptui.Prompt{
			Label: color.FgBlue.Sprintf("Enter password for %s or X to quit", account),
			Mask:  '*',
		}
		accountpword, err = prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return false
		}
		if strings.EqualFold(accountpword, "X") {
			return false
		}

		switch strings.ToUpper(bindmethod) {
		case "SIMPLE":
			logmsg.Println("Performing simple bind")
			err = conn.Bind(accountdn, accountpword)
			if err != nil {
				color.Error.Printf("Failed to bind with supplied credentials. %s", err)
			} else {
				color.Success.Println("LDAP Admin credentials successfully verified")
				promptContinue(color.Question.Sprintf("Continue to search for DHS User Roles"), "Y")
				return true
			}
		case "MD5":
			logmsg.Println("Performing MD5 bind")
			err = conn.MD5Bind(hostname, accountdn, accountpword)
			if err != nil {
				if secure {
					color.Error.Printf("MD5 Bind failed this could be because LDAPS is configured. %s", err)
					color.Error.Printf("If you continue and the your credentials are incorrect further tests could fail.")
					promptContinue(color.Question.Sprintf("Continue"), "Y")
				}
			} else {
				color.Success.Println("LDAP Admin credentials successfully verified")
				promptContinue(color.Question.Sprintf("Continue to search for DHS User Roles"), "Y")
				return true
			}
		default:
			color.Error.Printf("Bind method %s not recognized.", bindmethod)
			retval = false
			//os.Exit(0)
		}
		color.Success.Println("LDAP Default user credentials successfully verified")

	}
	promptContinue(color.Question.Sprintf("Continue to search for DHS User Roles"), "Y")
	return retval
}

func checkRolesDN(conn *ldap.Conn, configJson ConfigJson, basedn string, memberofattribute string, ldapattribute string) {
	//color.Success.Println("Searching LDAP for Roles..")

	banner("Searching LDAP for DHS Roles")

	for _, role := range configJson.Roles {
		r := roleStruct{}
		r.rolename = role[0]
		for i := 1; i < len(role); i++ {
			r.externalDN = append(r.externalDN, role[i])
			//color.Success.Println("Searching LDAP for Role ", role,  "accounts..")
			filter := fmt.Sprintf("(%s=%s)", memberofattribute, role[i])
			result, err := conn.Search(ldap.NewSearchRequest(
				basedn,
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				filter,
				[]string{ldapattribute, "objectClass", viper.GetString("member-attribute")},
				nil,
			))
			if err != nil {
				color.Error.Println("Unable to perform subtree search of basedn %s - %s", basedn, err)
				os.Exit(0)
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Userid", "User DN", "Evaluation Duration"})
			table.SetColMinWidth(1, 80)
			table.SetAutoWrapText(false)
			table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

			var accounts [][]string
			color.Warn.Println("")
			color.Warn.Println("")
			start := time.Now()
			logmsg.Println("The following users have", role[0], "Role access with External DN", role[i])
			for _, entry := range result.Entries {
				accounts = append(accounts, []string{entry.GetAttributeValue(ldapattribute), entry.DN})
				if contains(entry.GetAttributeValues("objectClass"), "group") {
					//log.Println(spew.Sdump(entry.GetAttributeValues(viper.GetString("member-attribute"))))
					//TODO Nested check, if no nested search requested just print the group DN details.
					// entry.PrettyPrint(3)
					checkNestedGroupRoles(conn, entry.GetAttributeValues(viper.GetString("member-attribute")), viper.GetString("member-attribute"), ldapattribute, table)
				} else {
					duration := time.Since(start)
					//logmsg.Println("Evaluation time:",duration)
					table.Append([]string{entry.GetAttributeValue(ldapattribute), entry.DN, duration.String()})
					//entry.PrettyPrint(3)
				}
			}

			table.Render()

		}
		roles = append(roles, r)
	}
	promptContinue(color.Question.Sprintf("Continue to generate Role mapping commands"), "Y")
}

func checkNestedGroupRoles(conn *ldap.Conn, values []string, getString string, ldapattribute string, table *tablewriter.Table) {
	for _, userdn := range values {
		filter := fmt.Sprintf("(distinguishedName=%s)", userdn)
		result, err := conn.Search(ldap.NewSearchRequest(
			userdn,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"objectClass", viper.GetString("member-attribute"), ldapattribute},
			nil,
		))
		if err != nil {
			color.Error.Println("Unable to perform subtree search of basedn - %s", err)
			os.Exit(0)
		}
		for _, entry := range result.Entries {
			if contains(entry.GetAttributeValues("objectClass"), "group") {
				//log.Println(spew.Sdump(entry.GetAttributeValues(viper.GetString("member-attribute"))))
				checkNestedGroupRoles(conn, entry.GetAttributeValues(viper.GetString("member-attribute")), viper.GetString("member-attribute"), ldapattribute, table)
			} else {
				table.Append([]string{entry.GetAttributeValue(ldapattribute), entry.DN})
				//entry.PrettyPrint(3)
			}
		}
	}
}

func checkAdminDN(conn *ldap.Conn, admindn string, basedn string, memberofattribute string, ldapattribute string) [][]string {
	//color.Success.Println("Searching LDAP for Security Admin DN accounts..")
	banner("Searching LDAP for Security Admin DN accounts")
	filter := fmt.Sprintf("(%s=%s)", memberofattribute, admindn)
	result, err := conn.Search(ldap.NewSearchRequest(
		basedn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{ldapattribute},
		nil,
	))

	if err != nil {
		color.Error.Println("Unable to perform subtree search of basedn %s - %s", basedn, err)
		os.Exit(0)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Userid", "User DN"})
	table.SetColMinWidth(1, 80)
	table.SetAutoWrapText(false)
	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	var adminaccounts [][]string
	logmsg.Println("The following users have Security Admin Role access.")
	color.Warn.Println("")
	for _, entry := range result.Entries {
		adminaccounts = append(adminaccounts, []string{entry.GetAttributeValue(ldapattribute), entry.DN})
		table.Append([]string{entry.GetAttributeValue(ldapattribute), entry.DN})
		//fmt.Printf(
		//	"%s: %s \n",
		//	color.FgCyan.Sprintf(entry.GetAttributeValue(ldapattribute)),
		//	color.FgBlue.Sprintf(entry.DN),
		//)
	}
	table.Render()
	color.Warn.Println("")
	promptContinue(color.Question.Sprintf("Continue to verify Admin account access"), "Y")
	return adminaccounts
}

func checkLdapAdminBind(hostname string, port string, secure bool, bindmethod string, defaultuser string, password string) *ldap.Conn {
	//color.Success.Println("Checking LDAP Default user credentials...")
	banner("Checking LDAP Default user credentials")
	net.JoinHostPort(hostname, port)
	var conn *ldap.Conn
	var err error
	var config *tls.Config
	if secure {
		config = &tls.Config{}
		config.InsecureSkipVerify = true
		logmsg.Println("Establishing secure connection to LDAP server.")
		conn, err = ldap.DialTLS("tcp", net.JoinHostPort(hostname, port), config)
		if viper.GetBool("debug") {
			log.Println(spew.Sdump(conn.TLSConnectionState()))
			conn.Debug.Enable(true)
		}
	} else {
		logmsg.Println("Establishing connection to LDAP server.")
		conn, err = ldap.Dial("tcp", net.JoinHostPort(hostname, port))
		if viper.GetBool("debug") {
			conn.Debug.Enable(true)
		}
	}
	if err != nil {
		color.Error.Printf("Failed to connect to LDAP Server. %s", err)
		os.Exit(0)
	}

	switch strings.ToUpper(bindmethod) {
	case "SIMPLE":
		logmsg.Println("Performing simple bind")
		err = conn.Bind(defaultuser, password)
		if err != nil {
			color.Error.Printf("Failed to bind with supplied credentials. %s", err)
			os.Exit(0)
		}
	case "MD5":
		logmsg.Println("Performing MD5 bind")
		err = conn.MD5Bind(hostname, defaultuser, password)
		if err != nil {
			if secure {
				color.Error.Printf("MD5 Bind failed this could be because LDAPS is configured. %s", err)
				color.Error.Printf("If you continue and the your credentials are incorrect further tests could fail.")
				promptContinue(color.Question.Sprintf("Continue"), "Y")
			}
		}
	default:
		color.Error.Printf("Bind method %s not recognized.", bindmethod)
		os.Exit(0)
	}
	color.Success.Println("LDAP Default user credentials successfully verified")
	promptContinue(color.Question.Sprintf("Continue to verify Admin accounts exist"), "Y")
	return conn
}

func checkConnectivity(a string, h string, port string) (int, int) {
	//color.Success.Println("Checking connectivity to LDAP server hosts...")
	banner("Checking connectivity to LDAP server hosts")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	hosts := strings.Split(a, ",")
	hosts = append(hosts, h)

	failures := 0
	successes := 0
	timeoutDuration := time.Duration(3000) * time.Millisecond
	intervalDuration := time.Duration(2) * time.Millisecond
	schema := ping.TCP.String()
	protocol, _ := ping.NewProtocol(schema)
	p, _ := strconv.Atoi(port)
	for i := range hosts {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{hosts[i]})
		table.SetColMinWidth(0, 100)
		table.SetAutoWrapText(false)
		table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor})
		table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor})
		addr, err := net.LookupIP(hosts[i])
		if err != nil {
			color.Error.Println("Unable to resolve hostname: ", hosts[i])
			failures += 1
			break
		}
		target := ping.Target{
			Timeout:  timeoutDuration,
			Interval: intervalDuration,
			Host:     addr[0].String(),
			Port:     p,
			Counter:  5,
			Protocol: protocol,
		}
		pinger := ping.NewTCPing()
		pinger.SetTarget(&target)
		pingerDone := pinger.Start()
		select {
		case <-pingerDone:
			break
		case <-sigs:
			break
		}
		var result []string
		result = append(result, fmt.Sprintf("%s", pinger.Result()))
		table.Append(result)
		table.Render()

		failures += pinger.Result().Failed()
		successes += pinger.Result().SuccessCounter
	}
	return successes, failures

}

func validateField(key string, masked bool) string {
	if viper.IsSet(key) {
		return viper.GetString(key)
	} else {
		field, err := getFieldValue(key, masked)
		if err != nil {
			panic(err)
		}
		return field
	}
}

func getFieldValue(key string, masked bool) (string, error) {
	if masked {
		prompt := promptui.Prompt{
			Label: key,
			Mask:  '*',
		}
		return prompt.Run()
	}
	prompt := promptui.Prompt{
		Label: key,
	}
	return prompt.Run()
}

func promptContinue(pstring string, def string) {
	println("")
	cont := def
	prompt := promptui.Prompt{
		Label:     pstring,
		IsConfirm: true,
		Default:   cont,
	}
	result, _ := prompt.Run()
	if result == "" {
		result = def
	}
	if strings.ToUpper(result) != "Y" {
		os.Exit(0)
	}
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func banner(s string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{s})
	table.SetColMinWidth(0, 100)
	table.SetAutoWrapText(false)
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor, tablewriter.BgBlueColor})
	table.Render()
}
