package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
