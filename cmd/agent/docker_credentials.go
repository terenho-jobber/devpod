package agent

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/skevetter/devpod/cmd/flags"
	"github.com/skevetter/devpod/pkg/debuglog"
	"github.com/skevetter/devpod/pkg/dockercredentials"
	"github.com/skevetter/log"
	"github.com/spf13/cobra"
)

// DockerCredentialsCmd holds the cmd flags.
type DockerCredentialsCmd struct {
	*flags.GlobalFlags

	Port int
}

// NewDockerCredentialsCmd creates a new command.
func NewDockerCredentialsCmd(flags *flags.GlobalFlags) *cobra.Command {
	cmd := &DockerCredentialsCmd{
		GlobalFlags: flags,
	}
	dockerCredentialsCmd := &cobra.Command{
		Use:   "docker-credentials",
		Short: "Retrieves docker-credentials from the local machine",
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return cmd.Run(cobraCmd.Context(), args, log.Default.ErrorStreamOnly())
		},
	}
	dockerCredentialsCmd.Flags().
		IntVar(&cmd.Port, "port", 0, "If specified, will use the given port")
	_ = dockerCredentialsCmd.MarkFlagRequired("port")
	return dockerCredentialsCmd
}

func (cmd *DockerCredentialsCmd) Run(ctx context.Context, args []string, log log.Logger) error {
	debuglog.Log("cmd/agent/docker-credentials invoked args=%v port=%d", args, cmd.Port)

	if len(args) == 0 {
		debuglog.Log("cmd/agent/docker-credentials early-return: no args")
		return nil
	}

	action := args[0]
	helper := dockercredentials.NewHelper(cmd.Port)

	// Capture stdin so we can log the server URL being requested AND replay
	// it to HandleCommand. This lets us see which registry the helper was
	// asked about without interfering with normal behavior.
	stdinBytes, readErr := io.ReadAll(os.Stdin)
	if readErr != nil {
		debuglog.Log("cmd/agent/docker-credentials stdin read error: %v", readErr)
	}
	debuglog.Log("cmd/agent/docker-credentials action=%q stdin=%q", action, string(stdinBytes))

	var outBuf bytes.Buffer
	stdout := io.MultiWriter(os.Stdout, &outBuf)

	if err := credentials.HandleCommand(helper, action, bytes.NewReader(stdinBytes), stdout); err != nil {
		log.Debugf("docker credentials command: %v", err)
		debuglog.Log("cmd/agent/docker-credentials HandleCommand error action=%q err=%v", action, err)
	} else {
		debuglog.Log("cmd/agent/docker-credentials HandleCommand ok action=%q stdout_len=%d stdout_tail=%q",
			action, outBuf.Len(), tailString(outBuf.String(), 80))
	}

	// Always return nil to fallback to anonymous access for public registries.
	return nil
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
