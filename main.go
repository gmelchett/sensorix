package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-ping/ping"
	"github.com/sasbury/mini"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	smtp "github.com/xhit/go-simple-mail/v2"
)

var mailEncryption = map[string]smtp.Encryption{
	"starttls": smtp.EncryptionSTARTTLS,
	"ssl":      smtp.EncryptionSSL,
	"tls":      smtp.EncryptionTLS,
	"ssltls":   smtp.EncryptionSSLTLS,
	"none":     smtp.EncryptionNone,
}

var mailAuth = map[string]smtp.AuthType{
	"none":    smtp.AuthNone,
	"login":   smtp.AuthLogin,
	"plain":   smtp.AuthPlain,
	"crammd5": smtp.AuthCRAMMD5,
}

type gotifyCfg struct {
	token    string
	host     string
	protocol string
	priority int64
}

type mailCfg struct {
	host       string
	port       int
	username   string
	password   string
	encryption string
	auth       string
	from       string
	to         string
}

type tempCfg struct {
	path      string
	warnlevel int64
}

type swapCfg struct {
	free uint64
}

type memCfg struct {
	free uint64
}

type pingCfg struct {
	packages int
	loss     int
	hosts    []string
}

type cpuCfg struct {
	stuck int
}

type cpuStat struct {
	cfg *cpuCfg
	isStuck bool
}

type diskCfg struct {
	mounts []string
	frees  []uint64
}

type lxdCfg struct {
	cmd string
}

type sensorix struct {
	interval           int
	notificationrepeat int
	gotify             *gotifyCfg
	mail               *mailCfg
	temperature        *tempCfg
	swap               *swapCfg
	memory             *memCfg
	ping               *pingCfg
	cpu                cpuStat
	disk               *diskCfg
	lxd                *lxdCfg
}

func toGiB(v uint64) uint64 {
	return v / 1024 / 1024 / 1024
}

func parseTemperatureConfig(cfg *mini.Config) *tempCfg {
	tc := &tempCfg{
		path:      cfg.StringFromSection("temperature", "path", ""),
		warnlevel: cfg.IntegerFromSection("temperature", "warnlevel", 0),
	}
	if tc.path == "" {
		log.Printf("WARNING: No path to temperature sensor.\n")
		return nil
	}
	if tc.warnlevel == 0 {
		log.Printf("WARNING: No temperature warning level given. Defaulting to 80°C\n")
		tc.warnlevel = 80
	}

	if _, err := ioutil.ReadFile(tc.path); err != nil {
		log.Printf("WARNING: Failed to read temperature path. Error: %v\n", err)
		return nil
	}
	return tc
}

func parseSwapConfig(cfg *mini.Config) *swapCfg {
	sc := &swapCfg{
		free: uint64(cfg.IntegerFromSection("swap", "free", 0)),
	}
	if sc.free == 0 {
		log.Printf("WARNING: No free swap check will be done.\n")
		return nil
	}

	if swapStat, err := mem.SwapMemory(); err == nil {
		tot := toGiB(swapStat.Total)
		if tot < sc.free {
			log.Printf("WARNING: Less actual swap space %d GiB than wanted free, %d GiB.\n",
				tot, sc.free)
			return nil
		}

		return sc
	} else {
		log.Printf("Failed to read swap settings: %v\n", err)
	}
	return nil
}

func parseMemConfig(cfg *mini.Config) *memCfg {
	mc := &memCfg{
		free: uint64(cfg.IntegerFromSection("mem", "free", 0)),
	}
	if mc.free == 0 {
		log.Printf("WARNING: No free memory check will be done.\n")
		return nil
	}

	if memStat, err := mem.VirtualMemory(); err == nil {
		tot := toGiB(memStat.Total)
		if tot < mc.free {
			log.Printf("WARNING: Less actual memory %d GiB than wanted free, %d GiB.\n",
				tot, mc.free)
			return nil
		}

		return mc
	} else {
		log.Printf("Failed to read mem settings: %v\n", err)
	}
	return nil
}

func parseGotifyConfig(cfg *mini.Config) *gotifyCfg {
	gt := &gotifyCfg{
		token:    cfg.StringFromSection("gotify", "token", ""),
		host:     cfg.StringFromSection("gotify", "host", ""),
		protocol: cfg.StringFromSection("gotify", "protocol", ""),
		priority: cfg.IntegerFromSection("gotify", "priority", 6),
	}
	if gt.token == "" || gt.host == "" {
		fmt.Println("WARNING: No gotify configuration found. Gotify notification disabled")
		return nil
	}
	if len(gt.protocol) == 0 {
		fmt.Println("WARNING: No protocol specified for gotify. Defaulting to https")
		gt.protocol = "https"
	}
	if gt.priority <= 0 || gt.priority > 10 {
		fmt.Println("WARNING: gotify: Invalid priority. Defaulting to 6.")
		gt.priority = 6
	}
	return gt
}

func parseLXDConfig(cfg *mini.Config) *lxdCfg {
	lc := &lxdCfg{
		cmd: cfg.StringFromSection("lxd", "cmd", ""),
	}
	if lc.cmd == "" {
		return nil
	}

	if finfo, err := os.Stat(lc.cmd); err == nil {
		if finfo.IsDir() {
			fmt.Println("WARNING: lxd: Given lxc binary is a directory.")
			return nil
		}
		return lc
	} else {
		fmt.Printf("WARNING: lxd: Troubles with potential lxc binary: %v\n", err)
		return nil
	}

}

func parsePingConfig(cfg *mini.Config) *pingCfg {

	hosts := cfg.StringFromSection("ping", "hosts", "")
	if len(hosts) == 0 {
		fmt.Println("WARNING: No hosts to ping")
		return nil
	}

	pc := &pingCfg{
		packages: int(cfg.IntegerFromSection("ping", "packages", 0)),
		loss:     int(cfg.IntegerFromSection("ping", "loss", 0)),
		hosts:    strings.Split(hosts, ","),
	}
	if pc.packages <= 0 {
		fmt.Println("WARNING: Invalid number of packages to send. Defaulting to 10.")
		pc.packages = 10
	}
	if pc.loss >= pc.packages {
		fmt.Println("WARNING: Allowing a  loss of packages that is higher or equal to packages to send. Turning off ping.")
		return nil
	}

	return pc
}

func parseDiskConfig(cfg *mini.Config) *diskCfg {
	mountStr := cfg.StringFromSection("disks", "mounts", "")
	if len(mountStr) == 0 {
		fmt.Println("WARNING: No disks to monitor")
		return nil
	}
	freeStr := cfg.StringFromSection("disks", "free", "")
	if len(freeStr) == 0 {
		fmt.Println("WARNING: No free space defined. Defaulting to 1 GiB")
		freeStr = "1"
	}

	var frees []uint64

	for _, c := range strings.Split(freeStr, ",") {
		if v, err := strconv.ParseUint(c, 10, 64); err == nil {
			frees = append(frees, v)
		} else {
			fmt.Println("WARNING: A free space(s) not a number. Defaulting to 1 GiB")
			frees = append(frees, 1)
		}
	}

	mounts := strings.Split(mountStr, ",")

	for len(frees) < len(mounts) {
		frees = append(frees, 1)
	}

	for i := range mounts {
		d, err := disk.Usage(mounts[i])
		if err != nil {
			fmt.Printf("WARNING: Disk check disabled. Inspecting mount point %s got error: %v", mounts[i], err)
		}
		if toGiB(d.Total) < frees[i] {
			fmt.Printf("WARNING: Disk at mountpoint %s is smaller (%d GiB) than wanted free space (%d GiB). Giving up.\n", mounts[i], toGiB(d.Total), frees[i])
			return nil
		}

	}
	return &diskCfg{mounts: mounts, frees: frees}
}

func parseCPUConfig(cfg *mini.Config) *cpuCfg {
	cc := &cpuCfg{
		stuck: int(cfg.IntegerFromSection("cpu", "stuck", 0)),
	}
	if cc.stuck == 0 {
		fmt.Println("WARNING: cpu at 100% for zero seconds is invalid, change to 60 minutes.")
		cc.stuck = 60
	}
	return cc
}

func parseMailConfig(cfg *mini.Config) *mailCfg {
	mcfg := &mailCfg{
		host:       cfg.StringFromSection("smtp", "host", ""),
		port:       int(cfg.IntegerFromSection("smtp", "port", 0)),
		username:   cfg.StringFromSection("smtp", "username", ""),
		password:   cfg.StringFromSection("smtp", "password", ""),
		encryption: cfg.StringFromSection("smtp", "encryption", ""),
		auth:       cfg.StringFromSection("smtp", "authentication", ""),
		from:       cfg.StringFromSection("smtp", "from", ""),
		to:         cfg.StringFromSection("smtp", "to", ""),
	}

	if mcfg.host == "" {
		fmt.Println("WARNING: Mail notification disabled.")
		return nil
	}

	if _, err := mail.ParseAddress(mcfg.from); err != nil {
		fmt.Println("WARNING: smtp: From field: ", err)
		return nil
	}
	if _, err := mail.ParseAddress(mcfg.to); err != nil {
		fmt.Println("WARNING: smtp: To field: ", err)
		return nil
	}

	if mcfg.port == 0 {
		fmt.Println("WARNING: Invalid port. Defaulting to 587.")
		mcfg.port = 587
	}

	if mcfg.encryption == "" {
		fmt.Println("WARNING: No encryption set. Defaulting to TLS.")
		mcfg.encryption = "tls"
	} else {
		if _, present := mailEncryption[mcfg.encryption]; !present {
			fmt.Println("WARNING: Invalid encryption for smtp. Mail off.")
			return nil
		}
	}

	if mcfg.auth == "" {
		fmt.Println("WARNING: No auth set. Defaulting to login.")
		mcfg.auth = "login"
	} else {
		if _, present := mailAuth[mcfg.auth]; !present {
			fmt.Println("WARNING: Invalid auth for smtp. Mail off.")
			return nil
		}
	}

	return mcfg
}

func (cs *cpuStat) thread() {
	if cs.cfg == nil {
		return
	}

	for {
		pload, _ := cpu.Percent(time.Duration(cs.cfg.stuck)*time.Minute, false)
		cs.isStuck = pload[0] > 100.0
	}
}

func (cs *cpuStat) check() error {
	if cs.cfg == nil {
		return nil
	}

	if cs.isStuck {
		return fmt.Errorf("CPU: WARNING: CPU is higher than 100%%")
	}
	return nil
}

func (sc *swapCfg) check() error {
	if sc == nil {
		return nil
	}

	if swapStat, err := mem.SwapMemory(); err == nil {
		free := toGiB(swapStat.Free)
		if free < sc.free {
			return fmt.Errorf("SWAP: WARNING: Wanted Free %d GiB - current %d GIB", sc.free, free)
		}
	} else {
		return fmt.Errorf("SWAP: WARNING: Failed reading swap stats: %v", err)
	}
	return nil
}

func (mc *memCfg) check() error {
	if mc == nil {
		return nil
	}

	if memStat, err := mem.VirtualMemory(); err == nil {

		free := toGiB(memStat.Available)

		if free < mc.free {
			return fmt.Errorf("MEMORY: WARNING: Wanted Free %d GiB - current %d GIB", mc.free, free)
		}
	} else {
		return fmt.Errorf("MEMORY: WARNING: Failed reading memory stats: %v", err)
	}
	return nil
}

func (tc *tempCfg) check() error {

	if tc == nil {
		return nil
	}

	var err error
	for retry := 0; retry < 5; retry++ {
		var d []byte
		d, err = ioutil.ReadFile(tc.path)

		if err == nil {
			if t, err := strconv.ParseInt(strings.Trim(string(d), "\n"), 10, 64); err == nil {
				if (t / 1000) < tc.warnlevel {
					return nil
				}
				return fmt.Errorf("TEMPERATURE: WARNING: Current temperature %d°C is above warning level %d°C", t/1000, tc.warnlevel)
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("TEMPERATURE: WARNING: Failed to read temperature. Five attempts failed. Error: %v", err)
}

func (dc *diskCfg) check() error {

	if dc == nil {
		return nil
	}

	errMsg := ""

	for i := range dc.mounts {
		d, err := disk.Usage(dc.mounts[i])
		if err != nil {
			errMsg += fmt.Sprintf("Inspecting mount point %s got error: %v", dc.mounts[i], err)
			continue
		}

		if toGiB(d.Free) < dc.frees[i] {
			errMsg += fmt.Sprintf("Disk at mountpoint %s has less free space (%d GiB) than wanted free space (%d GiB).",
				dc.mounts[i], toGiB(d.Free), dc.frees[i])
		}
	}

	if errMsg == "" {
		return nil
	}
	return fmt.Errorf("DISK: WARNING: %s", errMsg)
}

type lxcClusterList []struct {
	Roles         []string `json:"roles"`
	FailureDomain string   `json:"failure_domain"`
	Description   string   `json:"description"`
	Config        struct {
	} `json:"config"`
	Groups       []string `json:"groups"`
	ServerName   string   `json:"server_name"`
	URL          string   `json:"url"`
	Database     bool     `json:"database"`
	Status       string   `json:"status"`
	Message      string   `json:"message"`
	Architecture string   `json:"architecture"`
}

func (lx *lxdCfg) check() error {

	errch := make(chan error, 1)
	cmd := exec.Command(lx.cmd, "cluster", "list", "-f", "json")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("LXD: WARNING: Getting stdout \"%s\" failed with: %v", lx.cmd, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("LXD: WARNING: Start failed with: %v", err)
	}

	var result error

	go func() {

		var clusterStat lxcClusterList
		err = json.NewDecoder(stdout).Decode(&clusterStat)
		if err != nil {
			result = fmt.Errorf("LXD: WARNING: Failed parsing json output from lxc command")
			return
		}

		errMsg := ""
		for i := range clusterStat {
			if clusterStat[i].Status != "Online" {
				errMsg += fmt.Sprintf("\t%s status: %s\n", clusterStat[i].ServerName, clusterStat[i].Status)
			}
			if clusterStat[i].Message != "Fully operational" {
				errMsg += fmt.Sprintf("\t%s message: %s\n", clusterStat[i].ServerName, clusterStat[i].Message)
			}
		}
		if errMsg != "" {
			result = fmt.Errorf("LXD: WARNING:\n%s", errMsg)
			return
		}

		errch <- cmd.Wait()
	}()

	select {
	case <-time.After(time.Second * 5):
		cmd.Process.Kill()
		return fmt.Errorf("LXD: WARNING: lxc command timed out")
	case <-errch:
		return result
	}
}

func (pc *pingCfg) check() error {

	if pc == nil {
		return nil
	}

	errMsg := ""

	for i := range pc.hosts {

		pinger, err := ping.NewPinger(pc.hosts[i])
		if err != nil {
			errMsg += fmt.Sprintf("Create new pinger for host %s failed: %v\n", pc.hosts[i], err)
			continue
		}
		pinger.Count = pc.packages

		err = pinger.Run()
		if err != nil {
			errMsg += fmt.Sprintf("Running pinger failed: %v\n", err)
			continue
		}

		if (pinger.PacketsSent - pinger.PacketsRecv) > pc.loss {
			errMsg += fmt.Sprintf("Lost %d of %d pinging host: %s\n",
				(pinger.PacketsSent - pinger.PacketsRecv), pinger.PacketsSent,
				pc.hosts[i])
		}
	}
	if errMsg == "" {
		return nil
	}
	errMsg = strings.Trim(errMsg, "\n")
	return fmt.Errorf("PING: WARNING: %s", errMsg)
}

func (gt *gotifyCfg) send(title, msg string) {
	if gt == nil {
		return
	}

	postURL := fmt.Sprintf("%s://%s/message?token=%s", gt.protocol, gt.host, gt.token)

	resp, err := http.PostForm(postURL, url.Values{
		"title":    {title},
		"message":  {msg},
		"priority": {fmt.Sprintf("%d", gt.priority)},
	},
	)

	if err != nil {
		log.Printf("gotify send: Failed to create resource: %v\n", err)
		return
	}

	// Always close the response body
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("gotify send: status from server: %s\n", resp.Status)
	}
}

func (mc *mailCfg) send(title, msg string) {
	server := smtp.NewSMTPClient()

	server.Host = mc.host
	server.Port = mc.port
	server.Username = mc.username
	server.Password = mc.password

	server.Encryption = mailEncryption[mc.encryption]
	server.Authentication = smtp.AuthLogin
	server.KeepAlive = false
	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second
	smtpClient, err := server.Connect()

	if err != nil {
		log.Printf("WARNING: Failed connect to mail server: %s:%d. Error: %v\n", mc.host, mc.port, err)
		return
	}

	// New email simple html with inline and CC
	email := smtp.NewMSG()
	email.SetFrom(mc.from).
		AddTo(mc.to).
		SetSubject(title)

	email.SetBody(smtp.TextPlain, msg)
	err = email.Send(smtpClient)
	if err != nil {
		log.Printf("WARNING: Failed to send mail. Error: %v\n", err)
	}
}

func main() {
	var cfgFile string
	var testMail, testGotify bool

	flag.StringVar(&cfgFile, "c", "sensorix.conf", "Configuration file.")
	flag.BoolVar(&testMail, "m", false, "Send a test mail.")
	flag.BoolVar(&testGotify, "g", false, "Send a test gotify message.")
	flag.Parse()

	hn, err := os.Hostname()

	if err != nil {
		log.Fatal("Can't figure out hostname: ", err);
	}

	cfg, err := mini.LoadConfiguration(cfgFile)
	if err != nil {
		log.Fatal("Failed to load sensorix configuration", err)
	}

	sx := &sensorix{
		interval:           int(cfg.IntegerFromSection("sensorix", "interval", 60)),
		notificationrepeat: int(cfg.IntegerFromSection("sensorix", "notificationrepeat", 20)),
	}

	sx.gotify = parseGotifyConfig(cfg)
	sx.mail = parseMailConfig(cfg)

	if testMail {
		sx.mail.send("sensorix: Test mail", "\nHi,\nThis is a test mail sent from sensorix.\n")
	}

	if testGotify {
		sx.gotify.send("sensorix: Test message", "\nHi,\nThis is a test message sent from sensorix.\n")
	}

	sx.temperature = parseTemperatureConfig(cfg)
	sx.swap = parseSwapConfig(cfg)
	sx.memory = parseMemConfig(cfg)
	sx.ping = parsePingConfig(cfg)
	sx.cpu.cfg = parseCPUConfig(cfg)
	sx.disk = parseDiskConfig(cfg)
	sx.lxd = parseLXDConfig(cfg)

	go sx.cpu.thread()

	lastErrMsg := ""
	delayMult := 1
	nextAlert := 0

	for {
		time.Sleep(time.Duration(sx.interval) * time.Minute)

		errMsg := ""

		if err := sx.temperature.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.swap.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.memory.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.ping.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.cpu.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.disk.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.lxd.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}

		if len(errMsg) == 0 {
			delayMult = 1
			nextAlert = sx.interval
			lastErrMsg = ""
			continue
		}

		if errMsg != lastErrMsg {
			delayMult = 1
			nextAlert = sx.interval
		}

		nextAlert -= sx.interval
		if nextAlert > 0 {
			continue
		}

		nextAlert = sx.notificationrepeat * delayMult
		delayMult++

		lastErrMsg = errMsg

		title := fmt.Sprintf("sensorix: %s has ran into problems!", hn)

		log.Printf("WARNING: %s\n%s\n", title, errMsg)

		sx.gotify.send(title, title+"\n"+errMsg)
		sx.mail.send(title, title+"\n"+errMsg)
	}
}
