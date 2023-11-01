package main

import (
	"fmt"
	"log"
	"net/mail"
	"os"
	"strconv"
	"strings"

	"github.com/sasbury/mini"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

func parseTemperatureConfig(cfg *mini.Config) *tempCfg {
	tc := &tempCfg{
		warnlevel: cfg.IntegerFromSection("temperature", "warnlevel", 0),
	}

	if tc.warnlevel == 0 {
		log.Printf("WARNING: No temperature warning level given. Defaulting to 80°C\n")
		tc.warnlevel = 80
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
		return nil
	}
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
		return nil
	}
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
