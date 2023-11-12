package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/sasbury/mini"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
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
	cfg     *cpuCfg
	isStuck bool
}

type diskCfg struct {
	mounts []string
	frees  []uint64
}

type lxdCfg struct {
	cmd string
}

type externalIPCfg struct {
	hosts []string
	ipv4  bool
	ipv6  bool
}

type externalIP struct {
	cfg         *externalIPCfg
	currentIPv4 string
	currentIPv6 string
}

type writesCfg struct {
	amount  int64
	hours   int64
	devices []string
}

type writes struct {
	cfg         *writesCfg
	lastStats   map[string]disk.IOCountersStat
	overflowed  map[string]int64
	lastUpdated time.Time
}

type sensorix struct {
	interval           int
	notificationRepeat int
	lastUpdated        time.Time

	gotify      *gotifyCfg
	mail        *mailCfg
	temperature *tempCfg
	swap        *swapCfg
	memory      *memCfg
	ping        *pingCfg
	cpu         cpuStat
	disk        *diskCfg
	lxd         *lxdCfg
	externalIP  externalIP
	writes      writes
}

func toGiB(v uint64) uint64 {
	return v / 1024 / 1024 / 1024
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

	temps, _ := host.SensorsTemperatures() // Ignore the error code, seems to be broken

	msg := ""

	for n := range temps {
		if temps[n].Temperature > float64(tc.warnlevel) {
			msg += fmt.Sprintf("TEMPERATURE: WARNING: Current temperature %.1f°C on '%s' is above warning level %d.0°C\n", temps[n].Temperature, temps[n].SensorKey, tc.warnlevel)
		}
	}
	if msg != "" {
		return fmt.Errorf(msg)
	}
	return nil
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

	if lx == nil {
		return nil
	}

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

		pinger, err := probing.NewPinger(pc.hosts[i])
		if err != nil {
			errMsg += fmt.Sprintf("Create new pinger for host %s failed: %v\n", pc.hosts[i], err)
			continue
		}
		pinger.SetPrivileged(true)
		pinger.Count = pc.packages

		err = pinger.Run()
		if err != nil {
			execFullPath, _ := os.Executable()
			errMsg += fmt.Sprintf("ping failed: %v\nMaybe you need to run: 'setcap cap_net_raw=+ep %s'\n", err, execFullPath)
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

func httpGet(addr string, ipv4 bool) (string, error) {
	var zeroDialer net.Dialer
	var httpClient = &http.Client{
		Timeout: 4 * time.Second,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	networkType := "tcp4"

	if !ipv4 {
		networkType = "tcp6"
	}

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return zeroDialer.DialContext(ctx, networkType, addr)
	}
	httpClient.Transport = transport

	resp, err := httpClient.Get(addr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		return strings.TrimSpace(strings.ReplaceAll(string(body), "\n", "")), nil
	} else {
		return "", err
	}
}

func (wr *writes) check() error {

	if wr.cfg == nil {
		return nil
	}

	if !wr.lastUpdated.IsZero() && time.Now().Sub(wr.lastUpdated).Hours() < 1.0 {
		return nil
	}

	wr.lastUpdated = time.Now()

	s, err := disk.IOCounters(wr.cfg.devices...)

	if err != nil {
		return fmt.Errorf("WARNING: disk.IOCounters failed with: %v", err)
	}

	// first time.
	if len(wr.lastStats) == 0 {
		wr.lastStats = s
		return nil
	}

	errTxt := ""
	for _, dev := range wr.cfg.devices {

		delta := int64(s[dev].WriteBytes - wr.lastStats[dev].WriteBytes)
		if delta > wr.cfg.amount {
			wr.overflowed[dev]++
			if wr.overflowed[dev] >= wr.cfg.hours {
				errTxt += fmt.Sprintf("Device '%s' has written more than %d GiB per hour for the last %d hours.\n", dev,
					toGiB(uint64(wr.cfg.amount)), wr.cfg.hours)
			}
		} else {
			wr.overflowed[dev] = 0
		}
	}

	wr.lastStats = s
	if errTxt != "" {
		return fmt.Errorf("WRITE: %s\n", errTxt)
	}
	return nil

}

func (ei *externalIP) check() error {

	if ei.cfg == nil {
		return nil
	}

	errMsg := ""

	if ei.cfg.ipv4 {

		updated := false
		for _, h := range ei.cfg.hosts {
			addr, err := httpGet(h, true)
			if err != nil {
				continue
			}
			if ei.currentIPv4 == "" {
				ei.currentIPv4 = addr
			}
			if ei.currentIPv4 != addr {
				errMsg = fmt.Sprintf("External IPv4 address changed from: %s to: %s\n", ei.currentIPv4, addr)
				ei.currentIPv4 = addr
			}
			updated = true
			break
		}
		if !updated {
			errMsg = "Failed to fetch external IPv4 address.\n"
		}
	}

	if ei.cfg.ipv6 {

		updated := false
		for _, h := range ei.cfg.hosts {
			addr, err := httpGet(h, false)
			if err != nil {
				continue
			}
			if ei.currentIPv6 == "" {
				ei.currentIPv6 = addr
			}
			if ei.currentIPv6 != addr {
				errMsg += fmt.Sprintf("External IPv6 address changed from: %s to: %s\n", ei.currentIPv6, addr)
				ei.currentIPv6 = addr
			}
			updated = true
			break
		}
		if !updated {
			errMsg += "Failed to fetch external IPv6 address.\n"
		}
	}

	if errMsg != "" {
		return fmt.Errorf(errMsg)
	}
	return nil
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

func (sx *sensorix) startStatusServer(addr, port string) {

	l, err := net.Listen("tcp4", addr+":"+port)
	if err != nil {
		log.Fatalf("Cannot list to: %s:%s Error: %v\n", addr, port, err)
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Printf("WARNING: Failed to accept connection. Error: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			if !sx.lastUpdated.IsZero() {
				c.Write([]byte(fmt.Sprintf("sensorix: Last updated: %s\n", sx.lastUpdated.Format(time.RFC1123))))
			} else {
				c.Write([]byte(fmt.Sprintf("sensorix: Last updated: -\n")))
			}
			c.Close()
		}
	}()
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
		log.Fatal("Can't figure out hostname: ", err)
	}

	cfg, err := mini.LoadConfiguration(cfgFile)
	if err != nil {
		log.Fatal("Failed to load sensorix configuration", err)
	}

	sx := &sensorix{
		interval:           int(cfg.IntegerFromSection("sensorix", "interval", 1)),
		notificationRepeat: int(cfg.IntegerFromSection("sensorix", "notificationrepeat", 20)),
		writes:             writes{overflowed: make(map[string]int64)},
	}

	sx.startStatusServer(cfg.StringFromSection("sensorix", "addr", "localhost"), cfg.StringFromSection("sensorix", "port", "5678"))

	sx.gotify = parseGotifyConfig(cfg)
	sx.mail = parseMailConfig(cfg)

	if testMail {
		sx.mail.send("sensorix: Test mail", "\nHi,\nThis is a test mail sent from sensorix.\n")
	}

	if testGotify {
		sx.gotify.send("sensorix: Test message", "\nHi,\nThis is a test message sent from sensorix.\n")
	}

	if testMail || testGotify {
		os.Exit(0)
	}

	sx.temperature = parseTemperatureConfig(cfg)
	sx.swap = parseSwapConfig(cfg)
	sx.memory = parseMemConfig(cfg)
	sx.ping = parsePingConfig(cfg)
	sx.cpu.cfg = parseCPUConfig(cfg)
	sx.disk = parseDiskConfig(cfg)
	sx.lxd = parseLXDConfig(cfg)
	sx.externalIP.cfg = parseExternalIPConfig(cfg)
	sx.writes.cfg = parseWritesConfig(cfg)

	go sx.cpu.thread()

	lastErrMsg := ""
	delayMult := 1
	nextAlert := 0

	for {
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
		if err := sx.externalIP.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}
		if err := sx.writes.check(); err != nil {
			errMsg += fmt.Sprintf("\n%v", err)
		}

		if len(errMsg) > 0 {
			if errMsg != lastErrMsg {
				delayMult = 1
				nextAlert = sx.interval
			}

			nextAlert -= sx.interval
			if nextAlert <= 0 {

				nextAlert = sx.notificationRepeat * delayMult
				delayMult++

				title := fmt.Sprintf("sensorix: %s has ran into problems!", hn)

				log.Printf("WARNING: %s\n%s\n", title, errMsg)

				sx.gotify.send(title, title+"\n"+errMsg)
				sx.mail.send(title, title+"\n"+errMsg)
			}
		} else {
			delayMult = 1
			nextAlert = sx.interval
		}

		lastErrMsg = errMsg

		sx.lastUpdated = time.Now()

		time.Sleep(time.Duration(sx.interval) * time.Minute)
	}
}
