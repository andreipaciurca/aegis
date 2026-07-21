package ai

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DetectRuntimePlan selects a bounded local profile. It intentionally favors
// interactive response and available system memory over maximum benchmark
// throughput. Bigger models remain an explicit choice.
func DetectRuntimePlan(requested string) RuntimePlan {
	memoryGiB := detectMemoryGiB()
	plan := RuntimePlan{
		Profile:           ProfileCompact,
		ModelRef:          DefaultModelRef,
		MemoryGiB:         memoryGiB,
		CPUCount:          runtime.NumCPU(),
		Threads:           compactThreads(runtime.NumCPU()),
		ContextTokens:     1024,
		BatchSize:         128,
		EstimatedModelGiB: 2,
		Recommended:       true,
		Reason:            "Compact profile: Gemma 3 1B with a small context and bounded CPU use, selected to keep Aegis responsive while you work.",
	}
	if requested != ProfileBalanced {
		return plan
	}

	plan.Profile = ProfileBalanced
	plan.ModelRef = BalancedModelRef
	plan.ContextTokens = 2048
	plan.BatchSize = 256
	plan.Threads = balancedThreads(runtime.NumCPU())
	plan.EstimatedModelGiB = 5
	plan.GPUOffload = runtime.GOOS == "darwin" && memoryGiB >= 16
	plan.Recommended = memoryGiB >= 16
	plan.Reason = "Balanced profile: Gemma 3 4B for stronger explanations. It needs at least 16 GB of memory headroom; Aegis will keep CPU threads and context bounded."
	if memoryGiB > 0 && memoryGiB < 16 {
		plan.Reason = "Balanced profile requested, but this machine reports under 16 GB memory. Use compact mode to avoid swapping or severe slowdowns."
	}
	if plan.GPUOffload {
		plan.Reason += " Apple Silicon GPU offload is enabled because unified memory headroom is sufficient."
	}
	return plan
}

func compactThreads(cpus int) int {
	threads := cpus / 3
	if threads < 2 {
		threads = 2
	}
	if threads > 3 {
		threads = 3
	}
	return threads
}

func balancedThreads(cpus int) int {
	threads := cpus / 2
	if threads < 2 {
		threads = 2
	}
	if threads > 4 {
		threads = 4
	}
	return threads
}

func detectMemoryGiB() int {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "MemTotal:" {
					if kib, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						return int((kib*1024 + (1<<30 - 1)) >> 30)
					}
				}
			}
		}
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "sysctl", "-n", "hw.memsize")
	case "windows":
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "[int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	default:
		return 0
	}
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || bytes <= 0 {
		return 0
	}
	return int((bytes + (1<<30 - 1)) >> 30)
}
