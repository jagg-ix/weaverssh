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
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessionfsops"
	"weaverssh/sessionresume"
)

type transactionalCopyArguments struct {
	Recursive        bool
	ReplaceTree      bool
	PreserveMetadata bool
	Operands         []string
}

func parseTransactionalCopyArguments(args []string) (transactionalCopyArguments, error) {
	parsed := transactionalCopyArguments{PreserveMetadata: true}
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
			case "--replace", "--replace-tree":
				parsed.ReplaceTree = true
				continue
			case "--no-preserve-metadata":
				parsed.PreserveMetadata = false
				continue
			}
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return parsed, fmt.Errorf("unknown option %q", arg)
			}
		}
		parsed.Operands = append(parsed.Operands, arg)
	}
	if len(parsed.Operands) != 2 {
		return parsed, errors.New("cp needs exactly SOURCE and DESTINATION")
	}
	return parsed, nil
}

func cmdFileVerbTransactional(verb string, args []string) int {
	normalized := normalizeSessionAliasArgs(args)
	switch verb {
	case "cp":
		return cmdSessionCopyTransactional(normalized, os.Stdin, os.Stdout, os.Stderr)
	case "stat":
		return cmdSessionStatRich(normalized, os.Stdout, os.Stderr)
	default:
		return cmdFileVerbComplete(verb, normalized)
	}
}

func cmdSessionCopyTransactional(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := parseTransactionalCopyArguments(args)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 2
	}
	if !parsed.Recursive {
		return cmdSessionCopyComplete(parsed.Operands, stdin, stdout, stderr)
	}
	sourceRaw, destinationRaw := parsed.Operands[0], parsed.Operands[1]
	source, sourceRemote, sourceErr := parseSessionPath(sourceRaw)
	destination, destinationRemote, destinationErr := parseSessionPath(destinationRaw)
	if sourceErr != nil || destinationErr != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", firstError(sourceErr, destinationErr))
		return 2
	}
	ctx := context.Background()
	var copyErr error
	switch {
	case !sourceRemote && !destinationRemote:
		return runVFSCommand(append([]string{"cp"}, args...))
	case !sourceRemote && destinationRemote:
		copyErr = copyLocalTreeToSession(ctx, sourceRaw, destination, parsed)
	case sourceRemote && !destinationRemote:
		copyErr = copySessionTreeToLocal(ctx, source, destinationRaw, parsed)
	case sourceRemote && destinationRemote:
		if !isConcreteRemoteCopyNode(source.Node) || !isConcreteRemoteCopyNode(destination.Node) {
			copyErr = errors.New("remote-to-remote tree copy requires concrete signed node IDs")
		} else {
			copyErr = copySessionTreeToSession(ctx, source, destination, parsed)
		}
	}
	if copyErr != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", copyErr)
		return 1
	}
	return 0
}

func cmdSessionStatRich(args []string, stdout, stderr io.Writer) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("stat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(stderr, "usage: wv stat [--json] NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(operands[0])
	if err != nil || !matched {
		fmt.Fprintf(stderr, "wv stat: %v\n", firstError(err, errors.New("expected NODE:/path")))
		return 2
	}
	metadata, err := currentFSOpsClient(ref.Node).Lstat(context.Background(), ref.Path)
	if err != nil {
		return cmdSessionStatComplete(args, stdout, stderr)
	}
	result := map[string]any{
		"node":               ref.Node,
		"path":               metadata.Path,
		"name":               metadata.Name,
		"type":               metadata.Type,
		"size":               metadata.Size,
		"mode":               metadata.Mode,
		"mod_time_unix_nano": metadata.ModTimeUnixNano,
		"link_target":        metadata.LinkTarget,
	}
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintf(stderr, "wv stat: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(
		stdout,
		"node: %s\npath: /%s\nname: %s\ntype: %s\nsize: %d\nmode: %#o\nmtime-ns: %d\n",
		ref.Node,
		metadata.Path,
		metadata.Name,
		metadata.Type,
		metadata.Size,
		metadata.Mode&0o7777,
		metadata.ModTimeUnixNano,
	)
	if metadata.LinkTarget != "" {
		fmt.Fprintf(stdout, "link-target: %s\n", metadata.LinkTarget)
	}
	return 0
}

func currentFSOpsClient(node string) sessionfsops.Client {
	state, _ := sessionbroker.ActiveState()
	return sessionfsops.Client{Socket: state.Socket, Node: strings.TrimSpace(node)}
}

func copyLocalTreeToSession(ctx context.Context, localRoot string, destination sessionPath, options transactionalCopyArguments) error {
	rootInfo, err := os.Lstat(localRoot)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("recursive transactional source must be a real local directory")
	}
	rootAbs, err := filepath.Abs(localRoot)
	if err != nil {
		return err
	}
	client, err := activeSessionClient(ctx, destination.Node)
	if err != nil {
		return err
	}
	finalPath, err := resolveSessionDirectoryDestination(client, destination, filepath.Base(filepath.Clean(localRoot)))
	_ = client.Close()
	if err != nil {
		return err
	}
	ops := currentFSOpsClient(destination.Node)
	prepared, err := ops.PrepareTree(ctx, finalPath, uint32(rootInfo.Mode().Perm()), options.ReplaceTree)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = currentFSOpsClient(destination.Node).AbortTree(context.Background(), prepared.TempPath)
		}
	}()
	if err := uploadLocalTree(ctx, rootAbs, rootAbs, destination.Node, prepared.TempPath, options.PreserveMetadata); err != nil {
		return err
	}
	if err := verifyLocalEntryUnchanged(rootAbs, rootInfo); err != nil {
		return fmt.Errorf("source root changed during transactional copy: %w", err)
	}
	result, err := currentFSOpsClient(destination.Node).CommitTree(ctx, prepared.TempPath, finalPath, options.ReplaceTree)
	if err != nil {
		return err
	}
	committed = true
	if result.BackupPath != "" {
		_ = currentFSOpsClient(destination.Node).AbortTree(context.Background(), result.BackupPath)
	}
	return nil
}

func uploadLocalTree(ctx context.Context, localRoot, localDir, node, remoteDir string, preserve bool) error {
	directorySnapshot, err := os.Lstat(localDir)
	if err != nil {
		return err
	}
	if !directorySnapshot.IsDir() || directorySnapshot.Mode()&os.ModeSymlink != 0 {
		return errors.New("local source directory changed type during transactional copy")
	}
	client, err := openCurrentP9Client(ctx, node)
	if err != nil {
		return err
	}
	if err := ensureSessionDirectory(client, remoteDir); err != nil {
		_ = client.Close()
		return err
	}
	_ = client.Close()
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		localChild := filepath.Join(localDir, entry.Name())
		remoteChild := path.Join(remoteDir, entry.Name())
		info, err := os.Lstat(localChild)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(localChild)
			if err != nil {
				return err
			}
			if err := validateLocalSourceSymlink(localRoot, localChild, target); err != nil {
				return err
			}
			if err := currentFSOpsClient(node).Symlink(ctx, remoteChild, filepath.ToSlash(target), false); err != nil {
				return err
			}
			if err := verifyLocalSymlinkUnchanged(localChild, target); err != nil {
				return err
			}
		case info.IsDir():
			if err := uploadLocalTree(ctx, localRoot, localChild, node, remoteChild, preserve); err != nil {
				return err
			}
			if preserve {
				if err := currentFSOpsClient(node).SetMetadata(ctx, remoteChild, uint32(info.Mode().Perm()), info.ModTime()); err != nil {
					return err
				}
			}
		case info.Mode().IsRegular():
			if err := createRemoteEmptyFile(ctx, node, remoteChild, uint32(info.Mode().Perm())); err != nil {
				return err
			}
			openSource := func(context.Context) (sessionresume.ReaderAtCloser, error) {
				if err := verifyLocalEntryUnchanged(localChild, info); err != nil {
					return nil, fmt.Errorf("source changed during resumable copy: %w", err)
				}
				return os.Open(localChild)
			}
			if _, err := sessionresume.Copy(
				ctx,
				openSource,
				func(openCtx context.Context) (sessionresume.WriterAtCloser, error) {
					return openRemoteWriterAt(openCtx, node, remoteChild)
				},
				sessionresume.CopyConfig{Size: info.Size()},
			); err != nil {
				return err
			}
			if err := verifyLocalEntryUnchanged(localChild, info); err != nil {
				return fmt.Errorf("source changed during resumable copy: %w", err)
			}
			if preserve {
				if err := currentFSOpsClient(node).SetMetadata(ctx, remoteChild, uint32(info.Mode().Perm()), info.ModTime()); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported local file type: %s", localChild)
		}
	}
	if err := verifyLocalEntryUnchanged(localDir, directorySnapshot); err != nil {
		return fmt.Errorf("source directory changed during transactional copy: %w", err)
	}
	if preserve {
		return currentFSOpsClient(node).SetMetadata(ctx, remoteDir, uint32(directorySnapshot.Mode().Perm()), directorySnapshot.ModTime())
	}
	return nil
}

func copySessionTreeToSession(ctx context.Context, source, destination sessionPath, options transactionalCopyArguments) error {
	root, err := currentFSOpsClient(source.Node).Lstat(ctx, source.Path)
	if err != nil {
		return err
	}
	if root.Type != "directory" {
		return errors.New("recursive transactional source is not a directory")
	}
	destinationClient, err := activeSessionClient(ctx, destination.Node)
	if err != nil {
		return err
	}
	finalPath, err := resolveSessionDirectoryDestination(destinationClient, destination, path.Base(source.Path))
	_ = destinationClient.Close()
	if err != nil {
		return err
	}
	if source.Node == destination.Node && pathWithin(path.Clean(source.Path), path.Clean(finalPath)) {
		return errors.New("refusing to copy a session directory into itself or its descendant")
	}
	prepared, err := currentFSOpsClient(destination.Node).PrepareTree(ctx, finalPath, root.Mode, options.ReplaceTree)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = currentFSOpsClient(destination.Node).AbortTree(context.Background(), prepared.TempPath)
		}
	}()
	if err := copyRemoteTree(ctx, source.Node, path.Clean(source.Path), source.Path, destination.Node, prepared.TempPath, options.PreserveMetadata); err != nil {
		return err
	}
	if err := verifyRemoteMetadataUnchanged(ctx, source.Node, source.Path, root); err != nil {
		return fmt.Errorf("source root changed during transactional copy: %w", err)
	}
	result, err := currentFSOpsClient(destination.Node).CommitTree(ctx, prepared.TempPath, finalPath, options.ReplaceTree)
	if err != nil {
		return err
	}
	committed = true
	if result.BackupPath != "" {
		_ = currentFSOpsClient(destination.Node).AbortTree(context.Background(), result.BackupPath)
	}
	return nil
}

func copyRemoteTree(ctx context.Context, sourceNode, sourceRoot, sourceDir, destinationNode, destinationDir string, preserve bool) error {
	directorySnapshot, err := currentFSOpsClient(sourceNode).Lstat(ctx, sourceDir)
	if err != nil {
		return err
	}
	if directorySnapshot.Type != "directory" {
		return errors.New("remote source directory changed type during transactional copy")
	}
	entries, err := currentFSOpsClient(sourceNode).ListAll(ctx, sourceDir)
	if err != nil {
		return err
	}
	client, err := openCurrentP9Client(ctx, destinationNode)
	if err != nil {
		return err
	}
	if err := ensureSessionDirectory(client, destinationDir); err != nil {
		_ = client.Close()
		return err
	}
	_ = client.Close()
	for _, metadata := range entries {
		sourcePath := path.Join(sourceDir, metadata.Name)
		destinationPath := path.Join(destinationDir, metadata.Name)
		switch metadata.Type {
		case "directory":
			if err := copyRemoteTree(ctx, sourceNode, sourceRoot, sourcePath, destinationNode, destinationPath, preserve); err != nil {
				return err
			}
			if preserve {
				if err := currentFSOpsClient(destinationNode).SetMetadata(ctx, destinationPath, metadata.Mode, time.Unix(0, metadata.ModTimeUnixNano)); err != nil {
					return err
				}
			}
		case "symlink":
			if err := validateRemoteTreeSymlink(sourceRoot, sourcePath, metadata.LinkTarget); err != nil {
				return err
			}
			if err := currentFSOpsClient(destinationNode).Symlink(ctx, destinationPath, metadata.LinkTarget, false); err != nil {
				return err
			}
			if err := verifyRemoteMetadataUnchanged(ctx, sourceNode, sourcePath, metadata); err != nil {
				return err
			}
		case "file":
			if err := createRemoteEmptyFile(ctx, destinationNode, destinationPath, metadata.Mode); err != nil {
				return err
			}
			openSource := func(openCtx context.Context) (sessionresume.ReaderAtCloser, error) {
				if err := verifyRemoteMetadataUnchanged(openCtx, sourceNode, sourcePath, metadata); err != nil {
					return nil, errors.New("source changed during resumable copy")
				}
				return openRemoteReaderAt(openCtx, sourceNode, sourcePath)
			}
			if _, err := sessionresume.Copy(
				ctx,
				openSource,
				func(openCtx context.Context) (sessionresume.WriterAtCloser, error) {
					return openRemoteWriterAt(openCtx, destinationNode, destinationPath)
				},
				sessionresume.CopyConfig{Size: metadata.Size},
			); err != nil {
				return err
			}
			if err := verifyRemoteMetadataUnchanged(ctx, sourceNode, sourcePath, metadata); err != nil {
				return errors.New("source changed during resumable copy")
			}
			if preserve {
				if err := currentFSOpsClient(destinationNode).SetMetadata(ctx, destinationPath, metadata.Mode, time.Unix(0, metadata.ModTimeUnixNano)); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported remote file type %q at %s:/%s", metadata.Type, sourceNode, sourcePath)
		}
	}
	if err := verifyRemoteMetadataUnchanged(ctx, sourceNode, sourceDir, directorySnapshot); err != nil {
		return fmt.Errorf("source directory changed during transactional copy: %w", err)
	}
	if preserve {
		return currentFSOpsClient(destinationNode).SetMetadata(ctx, destinationDir, directorySnapshot.Mode, time.Unix(0, directorySnapshot.ModTimeUnixNano))
	}
	return nil
}

func copySessionTreeToLocal(ctx context.Context, source sessionPath, destination string, options transactionalCopyArguments) error {
	root, err := currentFSOpsClient(source.Node).Lstat(ctx, source.Path)
	if err != nil {
		return err
	}
	if root.Type != "directory" {
		return errors.New("recursive transactional source is not a directory")
	}
	finalPath, err := resolveLocalDirectoryDestination(source.Path, destination)
	if err != nil {
		return err
	}
	parent := filepath.Dir(finalPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if _, err := os.Lstat(finalPath); err == nil && !options.ReplaceTree {
		return errors.New("local destination tree exists; use --replace-tree")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".wv-tree-download-*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := downloadRemoteTree(ctx, source.Node, path.Clean(source.Path), source.Path, staging, staging, options.PreserveMetadata); err != nil {
		return err
	}
	if err := verifyRemoteMetadataUnchanged(ctx, source.Node, source.Path, root); err != nil {
		return fmt.Errorf("source root changed during transactional copy: %w", err)
	}
	if err := commitLocalTree(staging, finalPath, options.ReplaceTree); err != nil {
		return err
	}
	committed = true
	return nil
}

func downloadRemoteTree(ctx context.Context, node, remoteRoot, remoteDir, localRoot, localDir string, preserve bool) error {
	directorySnapshot, err := currentFSOpsClient(node).Lstat(ctx, remoteDir)
	if err != nil {
		return err
	}
	if directorySnapshot.Type != "directory" {
		return errors.New("remote source directory changed type during transactional copy")
	}
	entries, err := currentFSOpsClient(node).ListAll(ctx, remoteDir)
	if err != nil {
		return err
	}
	for _, metadata := range entries {
		remotePath := path.Join(remoteDir, metadata.Name)
		localPath := filepath.Join(localDir, metadata.Name)
		switch metadata.Type {
		case "directory":
			if err := os.Mkdir(localPath, 0o755); err != nil {
				return err
			}
			if err := downloadRemoteTree(ctx, node, remoteRoot, remotePath, localRoot, localPath, preserve); err != nil {
				return err
			}
		case "symlink":
			if err := validateRemoteTreeSymlink(remoteRoot, remotePath, metadata.LinkTarget); err != nil {
				return err
			}
			if err := validateLocalDestinationSymlink(localRoot, localPath, metadata.LinkTarget); err != nil {
				return err
			}
			if err := os.Symlink(filepath.FromSlash(metadata.LinkTarget), localPath); err != nil {
				return err
			}
			if err := verifyRemoteMetadataUnchanged(ctx, node, remotePath, metadata); err != nil {
				return err
			}
		case "file":
			file, err := os.OpenFile(localPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				return err
			}
			_ = file.Close()
			openSource := func(openCtx context.Context) (sessionresume.ReaderAtCloser, error) {
				if err := verifyRemoteMetadataUnchanged(openCtx, node, remotePath, metadata); err != nil {
					return nil, errors.New("source changed during resumable copy")
				}
				return openRemoteReaderAt(openCtx, node, remotePath)
			}
			if _, err := sessionresume.Copy(
				ctx,
				openSource,
				func(context.Context) (sessionresume.WriterAtCloser, error) {
					return os.OpenFile(localPath, os.O_RDWR, 0)
				},
				sessionresume.CopyConfig{Size: metadata.Size},
			); err != nil {
				return err
			}
			if err := verifyRemoteMetadataUnchanged(ctx, node, remotePath, metadata); err != nil {
				return errors.New("source changed during resumable copy")
			}
		default:
			return fmt.Errorf("unsupported remote file type %q", metadata.Type)
		}
		if preserve && metadata.Type != "symlink" {
			if err := os.Chmod(localPath, os.FileMode(metadata.Mode&0o7777)); err != nil {
				return err
			}
			when := time.Unix(0, metadata.ModTimeUnixNano)
			if err := os.Chtimes(localPath, when, when); err != nil {
				return err
			}
		}
	}
	if err := verifyRemoteMetadataUnchanged(ctx, node, remoteDir, directorySnapshot); err != nil {
		return fmt.Errorf("source directory changed during transactional copy: %w", err)
	}
	if preserve {
		if err := os.Chmod(localDir, os.FileMode(directorySnapshot.Mode&0o7777)); err != nil {
			return err
		}
		when := time.Unix(0, directorySnapshot.ModTimeUnixNano)
		return os.Chtimes(localDir, when, when)
	}
	return nil
}

func commitLocalTree(staging, finalPath string, replace bool) error {
	if _, err := os.Lstat(finalPath); os.IsNotExist(err) {
		return os.Rename(staging, finalPath)
	} else if err != nil {
		return err
	} else if !replace {
		return errors.New("destination tree exists")
	}
	backup := filepath.Join(filepath.Dir(finalPath), fmt.Sprintf(".wv-tree-backup-%d", time.Now().UnixNano()))
	if err := os.Rename(finalPath, backup); err != nil {
		return err
	}
	if err := os.Rename(staging, finalPath); err != nil {
		_ = os.Rename(backup, finalPath)
		return err
	}
	// The new tree is already committed. Backup cleanup failure must not be
	// reported as transaction failure; a later cleanup pass may remove residue.
	_ = os.RemoveAll(backup)
	return nil
}

func pathWithin(root, candidate string) bool {
	return candidate == root || strings.HasPrefix(candidate, strings.TrimSuffix(root, "/")+"/")
}

func validateLocalSourceSymlink(root, linkPath, target string) error {
	if target == "" || strings.IndexByte(target, 0) >= 0 || filepath.IsAbs(filepath.FromSlash(target)) {
		return errors.New("unsafe local symlink target")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(target)))
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("local symlink target escapes copied tree")
	}
	return nil
}

func validateRemoteTreeSymlink(root, linkPath, target string) error {
	if target == "" || strings.IndexByte(target, 0) >= 0 || strings.HasPrefix(target, "/") || strings.Contains(target, "\\") {
		return errors.New("unsafe remote symlink target")
	}
	resolved := path.Clean(path.Join(path.Dir(linkPath), target))
	if !pathWithin(path.Clean(root), resolved) {
		return errors.New("remote symlink target escapes copied tree")
	}
	return nil
}

func validateLocalDestinationSymlink(root, linkPath, target string) error {
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(target)))
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("remote symlink target escapes destination tree")
	}
	return nil
}

func verifyLocalSymlinkUnchanged(linkPath, expectedTarget string) error {
	info, err := os.Lstat(linkPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("source symlink changed type")
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		return err
	}
	if target != expectedTarget {
		return errors.New("source symlink target changed")
	}
	return nil
}

func verifyLocalEntryUnchanged(filePath string, expected os.FileInfo) error {
	current, err := os.Lstat(filePath)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) ||
		current.Mode() != expected.Mode() ||
		current.Size() != expected.Size() ||
		current.ModTime().UnixNano() != expected.ModTime().UnixNano() {
		return errors.New("source identity or metadata changed")
	}
	return nil
}

func verifyRemoteMetadataUnchanged(ctx context.Context, node, remotePath string, expected sessionfsops.FileMetadata) error {
	current, err := currentFSOpsClient(node).Lstat(ctx, remotePath)
	if err != nil {
		return err
	}
	if current.Type != expected.Type ||
		current.Mode != expected.Mode ||
		current.Size != expected.Size ||
		current.ModTimeUnixNano != expected.ModTimeUnixNano ||
		current.LinkTarget != expected.LinkTarget {
		return errors.New("source identity or metadata changed")
	}
	return nil
}

type p9PositionFile struct {
	client *p9client.Client
	file   *p9client.File
}

func (f *p9PositionFile) ReadAt(buffer []byte, offset int64) (int, error) {
	return f.file.ReadAt(buffer, offset)
}

func (f *p9PositionFile) WriteAt(buffer []byte, offset int64) (int, error) {
	return f.file.WriteAt(buffer, offset)
}

func (f *p9PositionFile) Close() error {
	first := f.file.Close()
	if err := f.client.Close(); first == nil {
		first = err
	}
	return first
}

func openCurrentP9Client(ctx context.Context, node string) (*p9client.Client, error) {
	state, err := sessionbroker.ActiveState()
	if err != nil {
		return nil, err
	}
	return remoteCopyClient(ctx, state, node)
}

func openRemoteReaderAt(ctx context.Context, node, remotePath string) (sessionresume.ReaderAtCloser, error) {
	client, err := openCurrentP9Client(ctx, node)
	if err != nil {
		return nil, err
	}
	file, err := client.OpenFile(remotePath, p9client.OREAD)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &p9PositionFile{client: client, file: file}, nil
}

func openRemoteWriterAt(ctx context.Context, node, remotePath string) (sessionresume.WriterAtCloser, error) {
	client, err := openCurrentP9Client(ctx, node)
	if err != nil {
		return nil, err
	}
	file, err := client.OpenFile(remotePath, p9client.OWRITE)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &p9PositionFile{client: client, file: file}, nil
}

func createRemoteEmptyFile(ctx context.Context, node, remotePath string, mode uint32) error {
	client, err := openCurrentP9Client(ctx, node)
	if err != nil {
		return err
	}
	defer client.Close()
	file, err := client.CreateFile(remotePath, mode&0o777)
	if err != nil {
		return err
	}
	return file.Close()
}
