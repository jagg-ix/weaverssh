package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"weaverssh/internal/p9client"
)

type sessionCopyArguments struct {
	Recursive bool
	Operands  []string
}

func parseSessionCopyArguments(args []string) (sessionCopyArguments, error) {
	var parsed sessionCopyArguments
	options := true
	for _, arg := range args {
		if options {
			switch arg {
			case "--":
				options = false
				continue
			case "-r", "-R", "--recursive":
				parsed.Recursive = true
				continue
			}
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return sessionCopyArguments{}, fmt.Errorf("unknown option %q", arg)
			}
		}
		parsed.Operands = append(parsed.Operands, arg)
	}
	if len(parsed.Operands) != 2 {
		return sessionCopyArguments{}, errors.New("cp needs exactly SOURCE and DESTINATION")
	}
	return parsed, nil
}

// cmdFileVerbComplete is the public broker-aware file command dispatcher. It
// retains the fixed-endpoint VFS compatibility path when no explicit NODE:/path
// operand is present.
func cmdFileVerbComplete(verb string, args []string) int {
	normalized := normalizeSessionAliasArgs(args)
	switch verb {
	case "cp":
		return cmdSessionCopyComplete(normalized, os.Stdin, os.Stdout, os.Stderr)
	case "rm":
		return cmdSessionRemoveComplete(normalized, false, os.Stderr)
	case "rmdir":
		return cmdSessionRemoveComplete(normalized, true, os.Stderr)
	case "stat":
		return cmdSessionStatComplete(normalized, os.Stdout, os.Stderr)
	default:
		return cmdFileVerb(verb, normalized)
	}
}

func cmdSessionCopyComplete(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := parseSessionCopyArguments(args)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		fmt.Fprintln(stderr, "usage: wv cp [-r|--recursive] SOURCE DESTINATION")
		return 2
	}
	sourceRaw, destinationRaw := parsed.Operands[0], parsed.Operands[1]
	source, sourceRemote, sourceErr := parseSessionPath(sourceRaw)
	destination, destinationRemote, destinationErr := parseSessionPath(destinationRaw)
	if sourceErr != nil || destinationErr != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", firstError(sourceErr, destinationErr))
		return 2
	}
	if !sourceRemote && !destinationRemote {
		return runVFSCommand(append([]string{"cp"}, args...))
	}
	if sourceRemote && destinationRemote {
		if !isConcreteRemoteCopyNode(source.Node) || !isConcreteRemoteCopyNode(destination.Node) {
			fmt.Fprintln(stderr, "wv cp: remote-to-remote copy requires concrete signed node IDs; expand WVORIGIN or replace self/previous/next with a node ID")
			return 2
		}
		return copySessionPathToSession(source, destination, parsed.Recursive, stderr)
	}
	if sourceRemote {
		if err := copySessionPathToLocal(source, destinationRaw, parsed.Recursive, stdout); err != nil {
			fmt.Fprintf(stderr, "wv cp: %v\n", err)
			return 1
		}
		return 0
	}
	if err := copyLocalPathToSession(sourceRaw, destination, parsed.Recursive, stdin); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	return 0
}

func cmdSessionRemoveComplete(args []string, directoryOnly bool, stderr io.Writer) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recursive := fs.Bool("r", false, "remove directories recursively")
	recursiveLong := fs.Bool("recursive", false, "remove directories recursively")
	fs.BoolVar(recursive, "R", false, "remove directories recursively")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		if directoryOnly {
			fmt.Fprintln(stderr, "usage: wv rmdir NODE:/path")
		} else {
			fmt.Fprintln(stderr, "usage: wv rm [-r|--recursive] NODE:/path")
		}
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wv rm: %v\n", err)
		return 2
	}
	if !matched {
		return runVFSCommand(append([]string{"rm"}, args...))
	}
	if ref.Path == "" {
		fmt.Fprintln(stderr, "wv rm: refusing to remove the exported root")
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv rm: %v\n", err)
		return 1
	}
	defer client.Close()
	entry, err := client.Stat(ref.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv rm: stat %s:/%s: %v\n", ref.Node, ref.Path, err)
		return 1
	}
	if directoryOnly && !entry.IsDir {
		fmt.Fprintf(stderr, "wv rmdir: %s:/%s is not a directory\n", ref.Node, ref.Path)
		return 1
	}
	if entry.IsDir && !directoryOnly && !*recursive && !*recursiveLong {
		fmt.Fprintf(stderr, "wv rm: %s:/%s is a directory (use -r)\n", ref.Node, ref.Path)
		return 1
	}
	if entry.IsDir && (*recursive || *recursiveLong) {
		err = removeSessionTree(client, ref.Path)
	} else {
		err = client.Remove(ref.Path)
	}
	if err != nil {
		command := "rm"
		if directoryOnly {
			command = "rmdir"
		}
		fmt.Fprintf(stderr, "wv %s: %v\n", command, err)
		return 1
	}
	return 0
}

func removeSessionTree(client *p9client.Client, remotePath string) error {
	entries, err := client.List(remotePath)
	if err != nil {
		return fmt.Errorf("list %s: %w", remotePath, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		child := path.Join(remotePath, entry.Name)
		if entry.IsDir {
			if err := removeSessionTree(client, child); err != nil {
				return err
			}
		} else if err := client.Remove(child); err != nil {
			return fmt.Errorf("remove %s: %w", child, err)
		}
	}
	if err := client.Remove(remotePath); err != nil {
		return fmt.Errorf("remove directory %s: %w", remotePath, err)
	}
	return nil
}

type sessionStatResult struct {
	Node  string `json:"node"`
	Path  string `json:"path"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Size  uint64 `json:"size"`
	IsDir bool   `json:"is_dir"`
}

func cmdSessionStatComplete(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv stat [--json] NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched {
		fmt.Fprintf(stderr, "wv stat: %v\n", firstError(err, errors.New("expected NODE:/path")))
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv stat: %v\n", err)
		return 1
	}
	defer client.Close()
	entry, err := client.Stat(ref.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv stat: %v\n", err)
		return 1
	}
	kind := "file"
	if entry.IsDir {
		kind = "directory"
	}
	name := entry.Name
	if ref.Path == "" {
		name = "/"
	}
	result := sessionStatResult{Node: ref.Node, Path: ref.Path, Name: name, Type: kind, Size: entry.Size, IsDir: entry.IsDir}
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintf(stderr, "wv stat: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "node: %s\npath: /%s\nname: %s\ntype: %s\nsize: %d\n", result.Node, result.Path, result.Name, result.Type, result.Size)
	return 0
}

func copySessionPathToLocal(source sessionPath, destination string, recursive bool, stdout io.Writer) error {
	client, err := activeSessionClient(context.Background(), source.Node)
	if err != nil {
		return err
	}
	defer client.Close()
	info, err := client.Stat(source.Path)
	if err != nil {
		return fmt.Errorf("stat source %s:/%s: %w", source.Node, source.Path, err)
	}
	if !info.IsDir {
		if source.Path == "" {
			return errors.New("source must name a file")
		}
		return copySessionRegularToLocal(client, source.Path, destination, stdout)
	}
	if !recursive {
		return fmt.Errorf("%s:/%s is a directory (use -r)", source.Node, source.Path)
	}
	if destination == "-" {
		return errors.New("cannot copy a directory to stdout")
	}
	target, err := resolveLocalDirectoryDestination(source.Path, destination)
	if err != nil {
		return err
	}
	return copySessionDirectoryToLocal(client, source.Path, target)
}

func resolveLocalDirectoryDestination(sourcePath, destination string) (string, error) {
	if info, err := os.Stat(destination); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("local destination %s is not a directory", destination)
		}
		if sourcePath == "" {
			return destination, nil
		}
		return filepath.Join(destination, path.Base(sourcePath)), nil
	}
	if strings.HasSuffix(destination, string(os.PathSeparator)) {
		return "", fmt.Errorf("local destination directory does not exist: %s", destination)
	}
	return destination, nil
}

func copySessionRegularToLocal(client *p9client.Client, remotePath, destination string, stdout io.Writer) error {
	reader, err := client.OpenReader(remotePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if destination == "-" {
		_, err := io.CopyBuffer(stdout, reader, make([]byte, remoteCopyBufferSize))
		return err
	}
	finalPath := destination
	if info, err := os.Stat(destination); err == nil && info.IsDir() {
		finalPath = filepath.Join(destination, path.Base(remotePath))
	} else if strings.HasSuffix(destination, string(os.PathSeparator)) {
		return fmt.Errorf("local destination directory does not exist: %s", destination)
	}
	return writeLocalFileAtomically(finalPath, reader)
}

func copySessionDirectoryToLocal(client *p9client.Client, remoteDir, localDir string) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}
	entries, err := client.List(remoteDir)
	if err != nil {
		return fmt.Errorf("list %s: %w", remoteDir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		remoteChild := path.Join(remoteDir, entry.Name)
		localChild := filepath.Join(localDir, entry.Name)
		if entry.IsDir {
			if err := copySessionDirectoryToLocal(client, remoteChild, localChild); err != nil {
				return err
			}
			continue
		}
		reader, err := client.OpenReader(remoteChild)
		if err != nil {
			return fmt.Errorf("open %s: %w", remoteChild, err)
		}
		copyErr := writeLocalFileAtomically(localChild, reader)
		closeErr := reader.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func writeLocalFileAtomically(finalPath string, reader io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(finalPath), ".wv-download-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := io.CopyBuffer(temporary, reader, make([]byte, remoteCopyBufferSize)); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return err
	}
	committed = true
	return nil
}

func copyLocalPathToSession(source string, destination sessionPath, recursive bool, stdin io.Reader) error {
	client, err := activeSessionClient(context.Background(), destination.Node)
	if err != nil {
		return err
	}
	defer client.Close()
	if source == "-" {
		remotePath, err := resolveSessionFileDestination(client, destination, "")
		if err != nil {
			return err
		}
		if remotePath == "" {
			return errors.New("stdin upload requires a destination file name")
		}
		return copyReaderToSession(client, stdin, remotePath, 0o644)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to follow local symlink %s", source)
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory (use -r)", source)
		}
		remoteRoot, err := resolveSessionDirectoryDestination(client, destination, filepath.Base(filepath.Clean(source)))
		if err != nil {
			return err
		}
		return copyLocalDirectoryToSession(client, source, remoteRoot)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported local file type: %s", source)
	}
	remotePath, err := resolveSessionFileDestination(client, destination, filepath.Base(source))
	if err != nil {
		return err
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	return copyReaderToSession(client, file, remotePath, uint32(info.Mode().Perm()))
}

func resolveSessionFileDestination(client *p9client.Client, destination sessionPath, sourceBase string) (string, error) {
	remotePath := destination.Path
	if remotePath == "" || destination.TrailingSlash {
		if sourceBase == "" {
			return "", nil
		}
		return path.Join(remotePath, sourceBase), nil
	}
	if entry, err := client.Stat(remotePath); err == nil && entry.IsDir {
		if sourceBase == "" {
			return "", errors.New("stdin upload to a directory requires a destination file name")
		}
		return path.Join(remotePath, sourceBase), nil
	}
	return remotePath, nil
}

func resolveSessionDirectoryDestination(client *p9client.Client, destination sessionPath, sourceBase string) (string, error) {
	if sourceBase == "" || sourceBase == "." || sourceBase == string(os.PathSeparator) {
		return "", errors.New("directory source has no usable basename")
	}
	remotePath := destination.Path
	if remotePath == "" || destination.TrailingSlash {
		return path.Join(remotePath, sourceBase), nil
	}
	if entry, err := client.Stat(remotePath); err == nil {
		if !entry.IsDir {
			return "", fmt.Errorf("destination %s:/%s is not a directory", destination.Node, remotePath)
		}
		return path.Join(remotePath, sourceBase), nil
	}
	return remotePath, nil
}

func ensureSessionDirectory(client *p9client.Client, remoteDir string) error {
	remoteDir = strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(remoteDir, "/")), "/")
	if remoteDir == "" || remoteDir == "." {
		return nil
	}
	if entry, err := client.Stat(remoteDir); err == nil {
		if !entry.IsDir {
			return fmt.Errorf("%s is not a directory", remoteDir)
		}
		return nil
	}
	parent := path.Dir(remoteDir)
	if parent != "." && parent != remoteDir {
		if err := ensureSessionDirectory(client, parent); err != nil {
			return err
		}
	}
	if err := client.Mkdir(remoteDir); err != nil {
		if entry, statErr := client.Stat(remoteDir); statErr == nil && entry.IsDir {
			return nil
		}
		return err
	}
	return nil
}

func copyLocalDirectoryToSession(client *p9client.Client, localDir, remoteDir string) error {
	if err := ensureSessionDirectory(client, remoteDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", remoteDir, err)
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		localChild := filepath.Join(localDir, entry.Name())
		remoteChild := path.Join(remoteDir, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to follow local symlink %s", localChild)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyLocalDirectoryToSession(client, localChild, remoteChild); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported local file type: %s", localChild)
		}
		file, err := os.Open(localChild)
		if err != nil {
			return err
		}
		copyErr := copyReaderToSession(client, file, remoteChild, uint32(info.Mode().Perm()))
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func copyReaderToSession(client *p9client.Client, reader io.Reader, remotePath string, permission uint32) error {
	writer, err := client.OpenWriter(remotePath, permission)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(writer, reader, make([]byte, remoteCopyBufferSize))
	closeErr := writer.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
