package smoke

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

const usage = "Usage: smoke --exe PATH --out DIRECTORY [--source-root DIRECTORY]\nNative Windows packaged GUI/engine ownership proof; writes safe summary.json.\n"

func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("smoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Flag errors can echo arbitrary caller arguments.
	executable := flags.String("exe", "", "packaged executable")
	output := flags.String("out", "", "owned output directory")
	source := flags.String("source-root", "", "source checkout root")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, _ = io.WriteString(stdout, usage)
			return 0
		}
		_, _ = fmt.Fprint(stderr, "smoke: invalid_arguments\n", usage)
		return 2
	}
	if *executable == "" || *output == "" || flags.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, "smoke: invalid_arguments\n", usage)
		return 2
	}
	summary := Run(ctx, Options{Executable: *executable, Output: *output, SourceRoot: *source})
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		_, _ = io.WriteString(stderr, "smoke: summary_output_failed\n")
		return 1
	}
	return summary.ExitStatus()
}
