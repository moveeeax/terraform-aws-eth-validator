// Command slashguard is a preflight check that is run on a validator host
// *before* the validator client is started, typically as part of a restore.
//
// It reads an EIP-3076 slashing-protection export and the keystore directory
// the host is about to load, and refuses the start when the combination could
// produce a second signing instance. It talks to nothing: no beacon node, no
// cloud API, no network at all. Everything it needs is a file on disk or a
// value the operator pastes in.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/moveeeax/terraform-aws-eth-validator/internal/audit"
	"github.com/moveeeax/terraform-aws-eth-validator/internal/interchange"
	"github.com/moveeeax/terraform-aws-eth-validator/internal/keystore"
	"github.com/moveeeax/terraform-aws-eth-validator/internal/report"
)

// version is overridden at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `slashguard — slashing-protection preflight for Ethereum validators

Usage:
  slashguard --interchange FILE [flags]

Flags:
  --interchange FILE          EIP-3076 slashing-protection export (required)
  --keystores DIR             directory of EIP-2335 keystores this host will load
  --genesis-validators-root R genesis validators root of the target network;
                              read it from the beacon node that will serve this
                              validator:
                                curl -s $BEACON/eth/v1/beacon/genesis \
                                  | jq -r .data.genesis_validators_root
  --current-epoch N           head epoch at the time of the restore
  --max-epoch-lag N           how many epochs behind head the export may be
                              before it is treated as stale (default 4)
  --format text|json|markdown output format (default text)
  --fail-on SEVERITY          exit non-zero at this severity or worse:
                              info, medium, high, critical (default high)
  --version                   print the version and exit

Exit codes:
  0  no finding at or above --fail-on
  1  at least one finding at or above --fail-on — do not start the validator
  2  the check could not run (bad flags, unreadable or unparseable input)

Checks that cannot run because an input was not supplied are listed in the
output as skipped. A pass with skipped checks is not a clean bill of health.
`

type config struct {
	interchangeFile string
	keystoreDir     string
	genesisRoot     string
	currentEpoch    int64
	maxEpochLag     uint64
	format          report.Format
	failOn          audit.Severity
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("slashguard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	var (
		interchangeFile = fs.String("interchange", "", "EIP-3076 export to check")
		keystoreDir     = fs.String("keystores", "", "keystore directory this host will load")
		genesisRoot     = fs.String("genesis-validators-root", "", "genesis validators root of the target network")
		currentEpoch    = fs.Int64("current-epoch", -1, "head epoch at the time of the restore")
		maxEpochLag     = fs.Uint64("max-epoch-lag", 4, "epochs behind head before the export is stale")
		formatFlag      = fs.String("format", "text", "text, json or markdown")
		failOnFlag      = fs.String("fail-on", "high", "info, medium, high or critical")
		showVersion     = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "slashguard %s\n", version)
		return 0
	}
	if *interchangeFile == "" {
		fmt.Fprint(stderr, usage)
		fmt.Fprintln(stderr, "\nerror: --interchange is required")
		return 2
	}

	format, err := report.ParseFormat(*formatFlag)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	failOn, err := audit.ParseSeverity(*failOnFlag)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	cfg := config{
		interchangeFile: *interchangeFile,
		keystoreDir:     *keystoreDir,
		genesisRoot:     *genesisRoot,
		currentEpoch:    *currentEpoch,
		maxEpochLag:     *maxEpochLag,
		format:          format,
		failOn:          failOn,
	}

	rep, err := check(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if err := report.Write(stdout, rep, cfg.format, cfg.failOn); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if rep.CountAtOrAbove(cfg.failOn) > 0 {
		return 1
	}
	return 0
}

func check(cfg config) (audit.Report, error) {
	f, err := os.Open(cfg.interchangeFile)
	if err != nil {
		return audit.Report{}, err
	}
	defer f.Close()

	doc, err := interchange.Parse(f)
	if err != nil {
		return audit.Report{}, fmt.Errorf("%s: %w", cfg.interchangeFile, err)
	}

	var ks *keystore.Set
	if cfg.keystoreDir != "" {
		ks, err = keystore.Load(cfg.keystoreDir)
		if err != nil {
			return audit.Report{}, fmt.Errorf("%s: %w", cfg.keystoreDir, err)
		}
	}

	opt := audit.Options{
		GenesisValidatorsRoot: cfg.genesisRoot,
		MaxEpochLag:           cfg.maxEpochLag,
	}
	if cfg.currentEpoch >= 0 {
		opt.CurrentEpoch, opt.HaveCurrentEpoch = uint64(cfg.currentEpoch), true
	}

	rep := audit.Run(doc, ks, opt)
	rep.InterchangeFile = cfg.interchangeFile
	return rep, nil
}
