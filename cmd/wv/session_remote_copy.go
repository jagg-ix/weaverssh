package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessionfsops"
	"weaverssh/sessionmux"
)

const remoteCopyBufferSize = 64 << 10

var remoteCopyStream = io.CopyBuffer

// trySessionRemoteCopy intercepts the public `wv cp` path only when both
// operands are explicit session paths. All other forms continue through the
// established local<->session implementation.
func trySessionRemoteCopy(args []string, stderr io.Writer) (bool, int) {
	parsed, err := parseSessionCopyArguments(args)
	if err != nil {
		return false, 0
	}
	source, sourceRemote, sourceErr := parseSessionPath(parsed.Operands[0])
	destination, destinationRemote, destinationErr := parseSessionPath(parsed.Operands[1])
	if sourceErr != nil || destinationErr != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", firstError(sourceErr, destinationErr))
		return true, 2
	}
	if !sourceRemote || !destinationRemote {
		return false, 0
	}
	if !isConcreteRemoteCopyNode(source.Node) || !isConcreteRemoteCopyNode(destination.Node) {
		fmt.Fprintln(stderr, "wv cp: remote-to-remote copy requires concrete signed node IDs; expand WVORIGIN or replace self/previous/next with a node ID")
		return true, 2
	}
	return true, copySessionPathToSession(source, destination, parsed.Recursive, stderr)
}

// copySessionToSession preserves the original regular-file entry point used by
// existing callers and tests.
func copySessionToSession(source, destination sessionPath, stderr io.Writer) int {
	return copySessionPathToSession(source, destination, false, stderr)
}

// copySessionPathToSession streams a regular file or, with recursive enabled, a
// directory tree between authenticated node-owned 9P endpoints. Directory
// creation is incremental; every regular-file destination remains transactional
// through the typed fs-ops prepare/commit protocol.
func copySessionPathToSession(source, destination sessionPath, recursive bool, stderr io.Writer) int {
	if source.Path == "" {
		fmt.Fprintln(stderr, "wv cp: source must name a file or directory below the exported root")
		return 2
	}
	ctx := context.Background()
	state, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	sourceClient, err := remoteCopyClient(ctx, state, source.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: open source node %s: %v\n", source.Node, err)
		return 1
	}
	defer sourceClient.Close()
	sourceInfo, err := sourceClient.Stat(source.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: stat source %s:/%s: %v\n", source.Node, source.Path, err)
		return 1
	}
	destinationClient, err := remoteCopyClient(ctx, state, destination.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: open destination node %s: %v\n", destination.Node, err)
		return 1
	}
	defer destinationClient.Close()
	destinationPath, err := resolveRemoteCopyDestination(destinationClient, destination, path.Base(source.Path))
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	if source.Node == destination.Node {
		if source.Path == destinationPath {
			fmt.Fprintln(stderr, "wv cp: source and destination are the same session file or directory")
			return 2
		}
		if sourceInfo.IsDir && strings.HasPrefix(destinationPath, strings.TrimSuffix(source.Path, "/")+"/") {
			fmt.Fprintln(stderr, "wv cp: refusing to copy a session directory into itself")
			return 2
		}
	}
	if !sourceInfo.IsDir {
		if err := copyRemoteRegularFile(ctx, state, sourceClient, destinationClient, source.Node, source.Path, destination.Node, destinationPath, stderr); err != nil {
			fmt.Fprintf(stderr, "wv cp: %v\n", err)
			return 1
		}
		return 0
	}
	if !recursive {
		fmt.Fprintln(stderr, "wv cp: recursive directory copy requires -r")
		return 2
	}
	if existing, statErr := destinationClient.Stat(destinationPath); statErr == nil && !existing.IsDir {
		fmt.Fprintf(stderr, "wv cp: destination %s:/%s is not a directory\n", destination.Node, destinationPath)
		return 1
	}
	if err := verifyRemoteCopyState(state); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	if err := ensureSessionDirectory(destinationClient, destinationPath); err != nil {
		fmt.Fprintf(stderr, "wv cp: create destination directory %s:/%s: %v\n", destination.Node, destinationPath, err)
		return 1
	}
	if err := copyRemoteDirectory(ctx, state, sourceClient, destinationClient, source, destination.Node, source.Path, destinationPath, stderr); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	return 0
}

func copyRemoteDirectory(
	ctx context.Context,
	state sessionbroker.State,
	sourceClient, destinationClient *p9client.Client,
	source sessionPath,
	destinationNode, sourceDir, destinationDir string,
	stderr io.Writer,
) error {
	entries, err := sourceClient.List(sourceDir)
	if err != nil {
		return fmt.Errorf("list source %s:/%s: %w", source.Node, sourceDir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		if err := verifyRemoteCopyState(state); err != nil {
			return err
		}
		sourceChild := path.Join(sourceDir, entry.Name)
		destinationChild := path.Join(destinationDir, entry.Name)
		if entry.IsDir {
			if existing, statErr := destinationClient.Stat(destinationChild); statErr == nil && !existing.IsDir {
				return fmt.Errorf("destination %s:/%s is not a directory", destinationNode, destinationChild)
			}
			if err := ensureSessionDirectory(destinationClient, destinationChild); err != nil {
				return fmt.Errorf("create destination directory %s:/%s: %w", destinationNode, destinationChild, err)
			}
			if err := copyRemoteDirectory(ctx, state, sourceClient, destinationClient, source, destinationNode, sourceChild, destinationChild, stderr); err != nil {
				return err
			}
			continue
		}
		if err := copyRemoteRegularFile(ctx, state, sourceClient, destinationClient, source.Node, sourceChild, destinationNode, destinationChild, stderr); err != nil {
			return err
		}
	}
	return nil
}

func copyRemoteRegularFile(
	ctx context.Context,
	state sessionbroker.State,
	sourceClient, destinationClient *p9client.Client,
	sourceNode, sourcePath, destinationNode, destinationPath string,
	stderr io.Writer,
) error {
	if err := verifyRemoteCopyState(state); err != nil {
		return err
	}
	reader, err := sourceClient.OpenReader(sourcePath)
	if err != nil {
		return fmt.Errorf("open source %s:/%s: %w", sourceNode, sourcePath, err)
	}
	operations := sessionfsops.Client{Socket: state.Socket, Node: destinationNode}
	operationCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	prepared, err := operations.PrepareReplace(operationCtx, destinationPath, 0o644, true)
	cancel()
	if err != nil {
		_ = reader.Close()
		return fmt.Errorf("prepare atomic destination %s:/%s: %w", destinationNode, destinationPath, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		abortCtx, abortCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer abortCancel()
		if abortErr := operations.AbortReplace(abortCtx, prepared.TempPath); abortErr != nil {
			fmt.Fprintf(stderr, "wv cp: warning: remove temporary destination %s:/%s: %v\n", destinationNode, prepared.TempPath, abortErr)
		}
	}()
	if err := verifyRemoteCopyState(state); err != nil {
		_ = reader.Close()
		return err
	}
	writer, err := destinationClient.OpenWriter(prepared.TempPath, prepared.AppliedMode)
	if err != nil {
		_ = reader.Close()
		return fmt.Errorf("open temporary destination %s:/%s: %w", destinationNode, prepared.TempPath, err)
	}
	buffer := make([]byte, remoteCopyBufferSize)
	_, copyErr := remoteCopyStream(writer, reader, buffer)
	readerCloseErr := reader.Close()
	writerCloseErr := writer.Close()
	if copyErr != nil {
		return fmt.Errorf("stream %s:/%s to temporary %s:/%s: %w", sourceNode, sourcePath, destinationNode, prepared.TempPath, copyErr)
	}
	if readerCloseErr != nil {
		return fmt.Errorf("close source %s:/%s: %w", sourceNode, sourcePath, readerCloseErr)
	}
	if writerCloseErr != nil {
		return fmt.Errorf("close temporary destination %s:/%s: %w", destinationNode, prepared.TempPath, writerCloseErr)
	}
	if err := verifyRemoteCopyState(state); err != nil {
		return err
	}
	commitCtx, commitCancel := context.WithTimeout(ctx, 15*time.Second)
	err = operations.CommitReplace(commitCtx, prepared.TempPath, destinationPath)
	commitCancel()
	if err != nil {
		return fmt.Errorf("commit atomic destination %s:/%s: %w", destinationNode, destinationPath, err)
	}
	committed = true
	return nil
}

func remoteCopyClient(ctx context.Context, state sessionbroker.State, node string) (*p9client.Client, error) {
	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := sessionbroker.Dial(openCtx, "unix", state.Socket, sessionbroker.OpenRequest{
		Node: node, Service: sessionmux.ServiceFS,
	})
	if err != nil {
		return nil, err
	}
	client, err := p9client.Attach(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func verifyRemoteCopyState(initial sessionbroker.State) error {
	current, err := sessionbroker.ActiveState()
	if err != nil {
		return fmt.Errorf("active session changed while preparing copy: %w", err)
	}
	if current.PID != initial.PID || current.Socket != initial.Socket || current.Binding != initial.Binding || current.Node != initial.Node {
		return errors.New("active session changed during remote copy; final destination was not committed")
	}
	return nil
}

func resolveRemoteCopyDestination(client remoteCopyStatClient, destination sessionPath, sourceBase string) (string, error) {
	if sourceBase == "" || sourceBase == "." || sourceBase == "/" {
		return "", errors.New("source path has no usable basename")
	}
	remotePath := destination.Path
	if remotePath == "" || destination.TrailingSlash {
		return path.Join(remotePath, sourceBase), nil
	}
	entry, err := client.Stat(remotePath)
	if err == nil && entry.IsDir {
		return path.Join(remotePath, sourceBase), nil
	}
	return remotePath, nil
}

func isConcreteRemoteCopyNode(node string) bool {
	switch strings.ToLower(strings.TrimSpace(node)) {
	case "self", "local", "here", "this", "current", ".", "previous", "prev", "next", "endpoint", "last", "remote":
		return false
	default:
		return strings.TrimSpace(node) != ""
	}
}

// remoteCopyStatClient keeps destination resolution testable without exposing
// the complete 9P client implementation.
type remoteCopyStatClient interface {
	Stat(string) (p9client.DirEntry, error)
}
