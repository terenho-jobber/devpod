package image

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/skevetter/log"
)

var (
	dockerTagRegexp  = regexp.MustCompile(`^[\w][\w.-]*$`)
	DockerTagMaxSize = 128
)

func GetImage(ctx context.Context, image string) (v1.Image, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	keychain, err := GetKeychain(ctx)
	if err != nil {
		return nil, fmt.Errorf("create authentication keychain: %w", err)
	}

	const debugRegistry = "873096713407.dkr.ecr.us-east-1.amazonaws.com"
	if ecrReg, parseErr := name.NewRegistry(debugRegistry); parseErr == nil {
		if auth, resolveErr := keychain.Resolve(ecrReg); resolveErr == nil {
			if authCfg, authErr := auth.Authorization(); authErr == nil {
				fmt.Fprintf(os.Stderr, "DEBUG ECR creds for %s: Username=%q Secret(len=%d)=%q\n",
					debugRegistry, authCfg.Username, len(authCfg.Password), authCfg.Password)
			} else {
				fmt.Fprintf(os.Stderr, "DEBUG ECR creds Authorization() error: %v\n", authErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG ECR creds Resolve() error: %v\n", resolveErr)
		}
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(&loggingKeychain{inner: keychain}))
	if err != nil {
		return nil, fmt.Errorf("retrieve image %s: %w", image, err)
	}

	return img, err
}

func GetImageForArch(ctx context.Context, image, arch string) (v1.Image, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	keychain, err := GetKeychain(ctx)
	if err != nil {
		return nil, fmt.Errorf("create authentication keychain: %w", err)
	}

	remoteOptions := []remote.Option{
		remote.WithAuthFromKeychain(keychain),
		remote.WithPlatform(v1.Platform{Architecture: arch, OS: "linux"}),
	}

	img, err := remote.Image(ref, remoteOptions...)
	if err != nil {
		return nil, fmt.Errorf("retrieve image %s: %w", image, err)
	}

	return img, err
}

func CheckPushPermissions(ctx context.Context, image string) error {
	ref, err := name.ParseReference(image)
	if err != nil {
		return fmt.Errorf("parse image reference %q: %w", image, err)
	}

	keychain, err := GetKeychain(ctx)
	if err != nil {
		return fmt.Errorf("create authentication keychain: %w", err)
	}

	// Create a context-aware transport to propagate cancellations and timeouts
	transport := &contextAwareTransport{
		ctx:       ctx,
		transport: http.DefaultTransport,
	}

	if err := remote.CheckPushPermission(ref, keychain, transport); err != nil {
		return fmt.Errorf("check push permissions: %w", err)
	}

	return nil
}

// loggingKeychain wraps a keychain and logs every credential resolution so we
// can see exactly what remote.Image uses vs what our standalone debug block shows.
type loggingKeychain struct {
	inner authn.Keychain
}

func (l *loggingKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	auth, err := l.inner.Resolve(resource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG loggingKeychain Resolve(%s) error: %v\n", resource.RegistryStr(), err)
		return auth, err
	}
	authCfg, authErr := auth.Authorization()
	if authErr != nil {
		fmt.Fprintf(os.Stderr, "DEBUG loggingKeychain Authorization(%s) error: %v\n", resource.RegistryStr(), authErr)
	} else {
		fmt.Fprintf(os.Stderr, "DEBUG loggingKeychain resolved %s: Username=%q Secret(len=%d)=%q\n",
			resource.RegistryStr(), authCfg.Username, len(authCfg.Password), authCfg.Password)
	}
	return auth, nil
}

// contextAwareTransport wraps an http.RoundTripper to inject context into requests.
type contextAwareTransport struct {
	ctx       context.Context
	transport http.RoundTripper
}

func (t *contextAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.WithContext(t.ctx)
	return t.transport.RoundTrip(req)
}

func GetImageConfig(
	ctx context.Context,
	image string,
	log log.Logger,
) (*v1.ConfigFile, v1.Image, error) {
	log.Debugf("Getting image config for image '%s'", image)
	defer log.Debugf("Done getting image config for image '%s'", image)

	img, err := GetImage(ctx, image)
	if err != nil {
		return nil, nil, err
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("config file: %w", err)
	}

	return configFile, img, nil
}

func ValidateTags(tags []string) error {
	for _, tag := range tags {
		if !IsValidDockerTag(tag) {
			return fmt.Errorf(`%q is not a valid docker tag`, tag)
		}
	}
	return nil
}

func IsValidDockerTag(tag string) bool {
	return shouldNotBeSlugged(tag, dockerTagRegexp, DockerTagMaxSize)
}

func shouldNotBeSlugged(data string, regexp *regexp.Regexp, maxSize int) bool {
	return len(data) == 0 || regexp.Match([]byte(data)) && len(data) <= maxSize
}

func GetImageConfigForArch(
	ctx context.Context,
	image, arch string,
	log log.Logger,
) (*v1.ConfigFile, v1.Image, error) {
	log.Debugf("Getting image config for image '%s' with architecture '%s'", image, arch)
	defer log.Debugf("Done getting image config for image '%s' with architecture '%s'", image, arch)

	img, err := GetImageForArch(ctx, image, arch)
	if err != nil {
		return nil, nil, err
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("config file: %w", err)
	}

	return configFile, img, nil
}
