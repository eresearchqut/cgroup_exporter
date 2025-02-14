// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup1"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func NewCgroupV1Collector(paths []string, logger log.Logger) Collector {
	return NewExporter(paths, logger, false)
}

func subsystem() ([]cgroup1.Subsystem, error) {
	s := []cgroup1.Subsystem{
		cgroup1.NewCpuacct(*CgroupRoot),
		cgroup1.NewMemory(*CgroupRoot),
	}
	return s, nil
}

func getPbsInfo(jobid string, metric *CgroupMetric, logger log.Logger) {
	pbsHome := "/var/spool/PBS/"
	filename := filepath.Join(pbsHome, "mom_priv", "jobs", jobid+".SC")

	// submission script will only exist on primary node in multi-node jobs
	fileInfo, err := os.Stat(filename)
	if err != nil {
		level.Debug(logger).Log("msg", "Error statting file", "filename", filename, "err", err)
		return
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		level.Error(logger).Log("msg", "Not a syscall.Stat_t", "filename", filename, "ok", ok)
		return
	}

	uid := stat.Uid
	user, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		level.Error(logger).Log("msg", "Unable to lookup user", "user", user, "err", err)
		return
	}

	metric.uid = user.Uid
	metric.username = user.Username
	level.Debug(logger).Log("msg", "Job owner", "job", jobid, "owner", metric.username)
}

func getInfov1(name string, metric *CgroupMetric, logger log.Logger) {
	pathBase := filepath.Base(name)
	userSlicePattern := regexp.MustCompile("^user-([0-9]+).slice$")
	userSliceMatch := userSlicePattern.FindStringSubmatch(pathBase)
	if len(userSliceMatch) == 2 {
		metric.userslice = true
		metric.uid = userSliceMatch[1]
		user, err := user.LookupId(metric.uid)
		if err != nil {
			level.Error(logger).Log("msg", "Error looking up user slice uid", "uid", metric.uid, "err", err)
		} else {
			metric.username = user.Username
		}
		return
	}
	slurmPattern := regexp.MustCompile("^/slurm/uid_([0-9]+)/job_([0-9]+)$")
	slurmMatch := slurmPattern.FindStringSubmatch(name)
	if len(slurmMatch) == 3 {
		metric.job = true
		metric.uid = slurmMatch[1]
		metric.jobid = slurmMatch[2]
		user, err := user.LookupId(metric.uid)
		if err != nil {
			level.Error(logger).Log("msg", "Error looking up slurm uid", "uid", metric.uid, "err", err)
		} else {
			metric.username = user.Username
		}
		return
	}
	if strings.HasPrefix(name, "/torque") {
		metric.job = true
		pathBaseSplit := strings.Split(pathBase, ".")
		metric.jobid = pathBaseSplit[0]
		return
	}
	if strings.HasPrefix(name, "/pbs_jobs") {
		metric.job = true
		pathBaseSplit := strings.Split(pathBase, ".")
		metric.jobid = pathBaseSplit[0]
		getPbsInfo(pathBase, metric, logger)
		return
	}
}

func (e *Exporter) getMetricsv1(name string) (CgroupMetric, error) {
	metric := CgroupMetric{name: name}
	level.Debug(e.logger).Log("msg", "Loading cgroup", "root", *CgroupRoot, "path", name)
	ctrl, err := cgroup1.Load(cgroup1.StaticPath(name))
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to load cgroups", "path", name, "err", err)
		metric.err = true
		return metric, err
	}
	stats, err := ctrl.Stat(cgroup1.IgnoreNotExist)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to stat cgroups", "path", name, "err", err)
		metric.err = true
		return metric, err
	}
	if stats == nil {
		level.Error(e.logger).Log("msg", "Cgroup stats are nil", "path", name)
		metric.err = true
		return metric, err
	}
	if stats.CPU != nil {
		if stats.CPU.Usage != nil {
			metric.cpuUser = float64(stats.CPU.Usage.User) / 1000000000.0
			metric.cpuSystem = float64(stats.CPU.Usage.Kernel) / 1000000000.0
			metric.cpuTotal = float64(stats.CPU.Usage.Total) / 1000000000.0
		}
	}
	if stats.Memory != nil {
		metric.memoryRSS = float64(stats.Memory.TotalRSS)
		metric.memoryCache = float64(stats.Memory.TotalCache)
		if stats.Memory.Usage != nil {
			metric.memoryUsed = float64(stats.Memory.Usage.Usage)
			metric.memoryTotal = float64(stats.Memory.Usage.Limit)
			metric.memoryFailCount = float64(stats.Memory.Usage.Failcnt)
		}
		if stats.Memory.Swap != nil {
			metric.memswUsed = float64(stats.Memory.Swap.Usage)
			metric.memswTotal = float64(stats.Memory.Swap.Limit)
			metric.memswFailCount = float64(stats.Memory.Swap.Failcnt)
		}
	}
	cpusPath := fmt.Sprintf("%s/cpuset%s/cpuset.cpus", *CgroupRoot, name)
	if cpus, err := getCPUs(cpusPath, e.logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}
	procs, _ := ctrl.Processes(cgroup1.Devices, true)
	pids := make([]int, len(procs))
	for i, p := range procs {
		pids[i] = p.Pid
	}
	getInfov1(name, &metric, e.logger)
	getProcStats(pids, &metric, e.logger)
	if *collectProc {
		if len(pids) > 0 {
			level.Debug(e.logger).Log("msg", "Get process info", "pids", fmt.Sprintf("%v", pids))
			getProcInfo(pids, &metric, e.logger)
		} else {
			level.Error(e.logger).Log("msg", "Unable to get PIDs", "path", name)
			metric.err = true
		}
	}
	return metric, nil
}

func listCgroupsV1(root string, subsystems []string, name string, logger log.Logger) ([]string, error) {
	var cgroups []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				level.Error(logger).Log("msg", "Permission error accessing", "file", path, "err", err)
				return filepath.SkipDir
			}

			level.Error(logger).Log("msg", "Error accessing", "file", path, "err", err)
			return err
		}
		if !d.IsDir() {
			return nil
		}

		relPath := strings.TrimPrefix(path, root)
		subsystem, cgroupName, found := strings.Cut(strings.TrimPrefix(relPath, "/"), "/")
		cgroupName = "/" + cgroupName

		if subsystem != "" {
			// filter on subsystems used by parent cgroup
			if !slices.Contains(subsystems, subsystem) {
				return filepath.SkipDir
			}
			// filter on cgroup path
			if !strings.HasPrefix(cgroupName, name) {
				return nil
			}
			// only include children of the search path
			if cgroupName == name {
				return nil
			}
			// cgroup already in list
			if slices.Contains(cgroups, cgroupName) {
				return nil
			}
		}

		if found {
			cgroupPath := strings.TrimPrefix(relPath, "/"+subsystem)
			_, err := cgroup1.Load(cgroup1.StaticPath(cgroupPath))
			if err == nil {
				cgroups = append(cgroups, cgroupPath)
			} else {
				fmt.Println(err)
			}
		}

		return nil
	})

	return cgroups, err
}

func (e *Exporter) collectv1() ([]CgroupMetric, error) {
	var metrics []CgroupMetric
	for _, path := range e.paths {
		level.Debug(e.logger).Log("msg", "Loading cgroup", "root", *CgroupRoot, "path", path)
		control, err := cgroup1.Load(cgroup1.StaticPath(path), cgroup1.WithHiearchy(subsystem))
		if err != nil {
			level.Error(e.logger).Log("msg", "Error loading cgroup subsystem", "root", *CgroupRoot, "path", path, "err", err)
			metric := CgroupMetric{name: path, err: true}
			metrics = append(metrics, metric)
			continue
		}
		subsystems := control.Subsystems()
		subsystemNames := make([]string, len(subsystems))
		for i, s := range subsystems {
			subsystemNames[i] = string(s.Name())
		}
		cgroupNames, _ := listCgroupsV1(*CgroupRoot, subsystemNames, path, e.logger)
		wg := &sync.WaitGroup{}
		wg.Add(len(cgroupNames))
		for _, name := range cgroupNames {
			go func(n string) {
				defer wg.Done()
				metric, _ := e.getMetricsv1(n)
				metricLock.Lock()
				metrics = append(metrics, metric)
				metricLock.Unlock()
			}(name)
		}
		wg.Wait()
	}
	return metrics, nil
}
