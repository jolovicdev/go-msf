package gomsf

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestIntegration_FullWorkflow(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	version, err := client.Core().Version(ctx)
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}
	t.Logf("Connected to Metasploit %s", version.Version)

	exploits, err := client.Modules().Exploits(ctx)
	if err != nil {
		t.Fatalf("Failed to list exploits: %v", err)
	}
	if len(exploits) == 0 {
		t.Error("No exploits found")
	}

	aux, err := client.Modules().Auxiliary(ctx)
	if err != nil {
		t.Fatalf("Failed to list auxiliary modules: %v", err)
	}
	if len(aux) == 0 {
		t.Error("No auxiliary modules found")
	}

	mod, err := client.Modules().Use(ctx, AuxiliaryModuleType, "scanner/portscan/tcp")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	options := mod.Options()
	if len(options) == 0 {
		t.Error("Module has no options")
	}

	required := mod.RequiredOptions()
	t.Logf("Module has %d required options", len(required))

	mod.SetOption("RHOSTS", "127.0.0.1")
	mod.SetOption("PORTS", "1-100")

	val, _ := mod.GetOption("RHOSTS")
	if val != "127.0.0.1" {
		t.Errorf("Expected RHOSTS to be 127.0.0.1, got %v", val)
	}

	sessions, err := client.Sessions().List(ctx)
	if err != nil {
		t.Fatalf("Failed to list sessions: %v", err)
	}
	t.Logf("Found %d active sessions", len(sessions))

	jobs, err := client.Jobs().List(ctx)
	if err != nil {
		t.Fatalf("Failed to list jobs: %v", err)
	}
	t.Logf("Found %d jobs", len(jobs))

	console, err := client.Consoles().Create(ctx)
	if err != nil {
		t.Fatalf("Failed to create console: %v", err)
	}
	t.Logf("Created console %s", console.ID)

	con, err := client.Consoles().GetConsole(ctx, console.ID)
	if err != nil {
		t.Fatalf("Failed to get console: %v", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	output, err := con.RunCommand(ctx2, "show auxiliary", 10*time.Second)
	if err != nil {
		t.Errorf("RunCommand failed: %v", err)
	}
	if output == "" {
		t.Error("Expected output from console command")
	}

	err = client.Consoles().Destroy(ctx, console.ID)
	if err != nil {
		t.Errorf("Failed to destroy console: %v", err)
	}

	workspaces, err := client.DB().Workspaces().List(ctx)
	if err != nil {
		t.Logf("Workspaces list failed (DB may not be connected): %v", err)
	} else {
		t.Logf("Found %d workspaces", len(workspaces))
	}

	tokens, err := client.Auth().TokenList(ctx)
	if err != nil {
		t.Fatalf("Failed to list tokens: %v", err)
	}
	t.Logf("Found %d tokens", len(tokens))

	t.Log("Integration test completed successfully")
}

func TestIntegration_ModuleMetadata(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	info, err := client.Modules().Info(ctx, ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Module info failed: %v", err)
	}
	if info.Name == "" || info.Rank == "" || len(info.References) == 0 {
		t.Fatalf("Expected metadata to be filled, got %+v", info)
	}
	if len(info.Targets) == 0 {
		t.Fatal("Expected targets inside module.info")
	}
	t.Logf("Module: %s rank=%s targets=%d refs=%d authors=%d",
		info.Name, info.Rank, len(info.Targets), len(info.References), len(info.Authors))

	payloads, err := client.Modules().CompatiblePayloads(ctx, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("CompatiblePayloads failed: %v", err)
	}
	if len(payloads) == 0 {
		t.Fatal("Expected at least one compatible payload")
	}

	mod, err := client.Modules().Use(ctx, ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	if mod.Info == nil || mod.Info.Name == "" {
		t.Fatal("Expected Module.Info to be filled by Use")
	}
	if len(mod.Targets()) == 0 {
		t.Fatal("Expected Module.Targets to expose module.info targets")
	}
}

func TestIntegration_DbReads(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	db := client.DB()

	console, err := client.Consoles().Create(ctx)
	if err != nil {
		t.Fatalf("Failed to create console: %v", err)
	}
	defer client.Consoles().Destroy(ctx, console.ID)

	con, err := client.Consoles().GetConsole(ctx, console.ID)
	if err != nil {
		t.Fatalf("Failed to get console: %v", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// A fresh console queues its banner before the first command; drain it so
	// the next RunCommand only carries its own output.
	if _, err := con.RunCommand(ctx2, "version", 20*time.Second); err != nil {
		t.Fatalf("console warm-up failed: %v", err)
	}
	if _, err := con.RunCommand(ctx2, "workspace", 20*time.Second); err != nil {
		t.Fatalf("workspace command failed: %v", err)
	}

	// Seed the database the way real tooling does: import an nmap XML.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not available, skipping db seeding: %v", err)
	}
	dockerExec(t, "cat > /tmp/gomsf-nmap.xml <<'XML'\n<?xml version=\"1.0\"?>\n<nmaprun scanner=\"nmap\" args=\"nmap -sV 10.99.0.1\" start=\"1\">\n<host><address addr=\"10.99.0.1\" addrtype=\"ipv4\"/><hostnames><hostname name=\"live-test-host\" type=\"PTR\"/></hostnames><status state=\"up\"/><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\" method=\"probed\" conf=\"10\"/></port></ports></host>\n<runstats><finished time=\"1700000000\"/></runstats>\n</nmaprun>\nXML")
	out, err := con.RunCommand(ctx2, "db_import /tmp/gomsf-nmap.xml", 30*time.Second)
	if err != nil {
		t.Fatalf("db_import failed: %v", err)
	}
	if !strings.Contains(out, "Sucessfully imported") && !strings.Contains(out, "Successfully imported") {
		t.Logf("db_import output: %s", out)
	}

	hosts, err := db.Hosts(ctx, nil)
	if err != nil {
		t.Fatalf("Hosts failed: %v", err)
	}
	found := false
	for _, h := range hosts {
		if h.Address == "10.99.0.1" {
			found = h.Name == "live-test-host"
		}
	}
	if !found {
		t.Fatalf("Expected reported host 10.99.0.1 in %d hosts", len(hosts))
	}

	services, err := db.Services(ctx, nil)
	if err != nil {
		t.Fatalf("Services failed: %v", err)
	}
	foundService := false
	for _, s := range services {
		if s.Host == "10.99.0.1" && s.Port == 22 {
			foundService = s.Name == "ssh"
		}
	}
	if !foundService {
		t.Fatalf("Expected reported ssh service in %d services", len(services))
	}

	vulns, err := db.Vulns(ctx, nil)
	if err != nil {
		t.Fatalf("Vulns failed: %v", err)
	}
	loots, err := db.Loots(ctx, nil)
	if err != nil {
		t.Fatalf("Loots failed: %v", err)
	}
	creds, err := db.Creds(ctx, nil)
	if err != nil {
		t.Fatalf("Creds failed: %v", err)
	}
	t.Logf("DB reads: %d hosts, %d services, %d vulns, %d loots, %d creds",
		len(hosts), len(services), len(vulns), len(loots), len(creds))

	if _, err := con.RunCommand(ctx2, "hosts -d 10.99.0.1", 20*time.Second); err != nil {
		t.Logf("cleanup hosts -d failed: %v", err)
	}
}

func TestIntegration_ReauthOnKilledToken(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	if _, err := client.Core().Version(ctx); err != nil {
		t.Fatalf("Version failed: %v", err)
	}

	// Kill the token server-side; the next call must recover transparently.
	if err := client.Auth().TokenRemove(ctx, client.Token()); err != nil {
		t.Fatalf("TokenRemove failed: %v", err)
	}

	version, err := client.Core().Version(ctx)
	if err != nil {
		t.Fatalf("Expected transparent re-auth after token removal, got %v", err)
	}
	t.Logf("Recovered via re-auth, Metasploit %s", version.Version)
}

func dockerExec(t *testing.T, command string) string {
	t.Helper()

	container := os.Getenv("GOMSF_TEST_CONTAINER")
	if container == "" {
		container = "gomsf-test"
	}

	out, err := exec.Command("docker", "exec", container, "bash", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %q failed: %v\n%s", command, err, out)
	}
	return string(out)
}

func TestIntegration_EventMonitor(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Stop leftovers from earlier runs so session/job diffs are deterministic.
	if sessions, err := client.Sessions().List(ctx); err == nil {
		for sid := range sessions {
			_ = client.Sessions().Stop(ctx, sid)
		}
	}
	if jobs, err := client.Jobs().List(ctx); err == nil {
		for id := range jobs {
			_ = client.Jobs().Stop(ctx, id)
		}
	}

	monitor := client.Events(ctx,
		WithEventSessionInterval(500*time.Millisecond),
		WithEventJobInterval(500*time.Millisecond),
		WithEventOutputInterval(500*time.Millisecond),
	)

	// Start a handler as a job: exercises job_started.
	_, err := client.Modules().Execute(ctx, ExploitModuleType, "multi/handler", map[string]interface{}{
		"PAYLOAD": "linux/x64/shell_reverse_tcp",
		"LHOST":   "127.0.0.1",
		"LPORT":   4444,
	})
	if err != nil {
		t.Fatalf("Failed to start handler: %v", err)
	}

	jobStarted := waitForLiveEvent(t, monitor.C(), EventJobStarted)
	t.Logf("Job started: %s %s", jobStarted.Job.ID, jobStarted.Job.Name)

	// Get a real session: generate a reverse shell with msfvenom inside the
	// msfrpcd container and run it against the handler.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not available, skipping session lifecycle part: %v", err)
	}
	dockerExec(t, "msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf -o /tmp/gomsf-shell")
	dockerExec(t, "chmod +x /tmp/gomsf-shell; nohup /tmp/gomsf-shell >/dev/null 2>&1 &")

	sessionOpened := waitForLiveEvent(t, monitor.C(), EventSessionOpened)
	if sessionOpened.SessionID == "" || sessionOpened.Session == nil {
		t.Fatalf("Expected session id and session on open event, got %+v", sessionOpened)
	}
	t.Logf("Session opened: id=%s type=%s", sessionOpened.SessionID, sessionOpened.Session.Type)

	monitor.WatchSession(sessionOpened.SessionID)
	if err := client.Sessions().Stop(ctx, sessionOpened.SessionID); err != nil {
		t.Fatalf("Session stop failed: %v", err)
	}
	waitForLiveEvent(t, monitor.C(), EventSessionClosed)
	t.Log("Session closed event received")

	if err := client.Jobs().Stop(ctx, jobStarted.Job.ID); err != nil {
		t.Fatalf("Job stop failed: %v", err)
	}
	waitForLiveEvent(t, monitor.C(), EventJobStopped)
	t.Log("Job stopped event received")
}
