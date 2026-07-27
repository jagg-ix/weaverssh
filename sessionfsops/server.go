package sessionfsops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"weaverssh/filebackend"
)

const (
	tempPrefix = ".wv-replace-"
	treeTempPrefix = ".wv-tree-"
	treeBackupPrefix = ".wv-tree-backup-"
)

type ServerConfig struct { Root string; ReadOnly bool; Backend filebackend.API }
type Server struct { root string; readOnly bool; backend filebackend.API }

func NewServer(config ServerConfig) (*Server, error) {
	root := strings.TrimSpace(config.Root)
	if config.Backend != nil {
		description := config.Backend.Describe()
		if root == "" { root = description.Root }
		config.ReadOnly = config.ReadOnly || description.ReadOnly
	}
	if root == "" { return nil, errors.New("sessionfsops: root is required") }
	absolute, err := filepath.Abs(root); if err != nil { return nil, err }
	resolved, err := filepath.EvalSymlinks(absolute); if err != nil { return nil, err }
	info, err := os.Stat(resolved); if err != nil { return nil, err }
	if !info.IsDir() { return nil, errors.New("sessionfsops: root is not a directory") }
	if config.Backend != nil {
		backendRoot, err := filepath.EvalSymlinks(config.Backend.Describe().Root)
		if err != nil || filepath.Clean(backendRoot) != filepath.Clean(resolved) { return nil, errors.New("sessionfsops: backend root does not match server root") }
	}
	return &Server{root: resolved, readOnly: config.ReadOnly, backend: config.Backend}, nil
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser) error {
	if s == nil || stream == nil { return errors.New("sessionfsops: incomplete server") }
	defer stream.Close()
	select { case <-ctx.Done(): return ctx.Err(); default: }
	request, err := readRequest(stream)
	if err != nil { _ = writeResponse(stream, errorResponse("", err)); return nil }
	if s.readOnly && mutatingOperation(request.Operation) { _ = writeResponse(stream, errorResponse(request.ID, ErrReadOnly)); return nil }
	var pending filebackend.Pending
	if s.backend != nil {
		pending, err = s.backend.Begin(ctx, backendEvent(request))
		if err != nil { return writeResponse(stream, errorResponse(request.ID, err)) }
	}
	var result Result
	switch request.Operation {
	case OperationPrepareReplace: result, err = s.prepareReplace(request)
	case OperationCommitReplace: result, err = s.commitReplace(request)
	case OperationAbortReplace: result, err = s.abortReplace(request)
	case OperationLstat: result, err = s.lstat(request)
	case OperationList: result, err = s.list(request)
	case OperationSymlink: result, err = s.symlink(request)
	case OperationSetMetadata: result, err = s.setMetadata(request)
	case OperationPrepareTree: result, err = s.prepareTree(request)
	case OperationCommitTree: result, err = s.commitTree(request)
	case OperationAbortTree: result, err = s.abortTree(request)
	default: err = ErrInvalidRequest
	}
	if s.backend != nil { s.backend.Complete(ctx, pending, err, backendMutationPaths(request, result, err)) }
	if err != nil { return writeResponse(stream, errorResponse(request.ID, err)) }
	return writeResponse(stream, Response{ID: request.ID, Result: result})
}

func mutatingOperation(operation string) bool {
	switch operation {
	case OperationLstat, OperationList: return false
	default: return true
	}
}

func backendEvent(request Request) filebackend.Event {
	event := filebackend.Event{Attributes: map[string]string{"protocol": ProtocolVersion, "request_id": strings.TrimSpace(request.ID), "fs_operation": request.Operation}, Mode: request.Mode}
	switch request.Operation {
	case OperationLstat: event.Operation = filebackend.OperationStat; event.Path = request.FinalPath
	case OperationList: event.Operation = filebackend.OperationReadDir; event.Path = request.FinalPath
	case OperationSymlink: event.Operation = filebackend.OperationCreate; event.Path = request.FinalPath; event.Attributes["link_target"] = request.LinkTarget
	case OperationSetMetadata: event.Operation = filebackend.OperationWrite; event.Path = request.FinalPath
	case OperationPrepareReplace, OperationPrepareTree: event.Operation = filebackend.OperationPrepareReplace; event.Path = request.FinalPath
	case OperationCommitReplace, OperationCommitTree: event.Operation = filebackend.OperationCommitReplace; event.Path = request.FinalPath; event.SecondaryPath = request.TempPath
	case OperationAbortReplace, OperationAbortTree: event.Operation = filebackend.OperationAbortReplace; event.Path = request.TempPath
	default: event.Operation = filebackend.OperationStat
	}
	return event
}

func backendMutationPaths(request Request, result Result, operationErr error) []string {
	if operationErr != nil || !mutatingOperation(request.Operation) { return nil }
	switch request.Operation {
	case OperationPrepareReplace, OperationPrepareTree: return []string{result.TempPath}
	case OperationCommitReplace, OperationCommitTree: return []string{request.TempPath, request.FinalPath}
	case OperationAbortReplace, OperationAbortTree: return []string{request.TempPath}
	case OperationSymlink, OperationSetMetadata: return []string{request.FinalPath}
	default: return nil
	}
}

func (s *Server) lstat(request Request) (Result, error) {
	relative, absolute, err := s.resolvePath(request.FinalPath)
	if err != nil { return Result{}, err }
	info, err := os.Lstat(absolute)
	if err != nil { return Result{}, err }
	metadata, err := fileMetadata(relative, absolute, info)
	if err != nil { return Result{}, err }
	return Result{Metadata: &metadata}, nil
}

func (s *Server) list(request Request) (Result, error) {
	relative, absolute, err := s.resolvePath(request.FinalPath)
	if err != nil { return Result{}, err }
	info, err := os.Lstat(absolute)
	if err != nil { return Result{}, err }
	if !info.IsDir() { return Result{}, fmt.Errorf("%w: list path is not a directory", ErrPathDenied) }
	entries, err := os.ReadDir(absolute); if err != nil { return Result{}, err }
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	limit := request.Limit; if limit <= 0 { limit = 256 }
	result := Result{Entries: make([]FileMetadata, 0, minInt(limit, len(entries)))}
	start := 0
	if request.Cursor != "" {
		start = sort.Search(len(entries), func(i int) bool { return entries[i].Name() > request.Cursor })
	}
	for index := start; index < len(entries) && len(result.Entries) < limit; index++ {
		name := entries[index].Name()
		childRelative := path.Join(relative, name)
		childAbsolute := filepath.Join(absolute, name)
		childInfo, err := os.Lstat(childAbsolute); if err != nil { return Result{}, err }
		metadata, err := fileMetadata(childRelative, childAbsolute, childInfo); if err != nil { return Result{}, err }
		result.Entries = append(result.Entries, metadata)
	}
	if start+len(result.Entries) < len(entries) && len(result.Entries) > 0 { result.NextCursor = result.Entries[len(result.Entries)-1].Name }
	return result, nil
}

func fileMetadata(relative, absolute string, info os.FileInfo) (FileMetadata, error) {
	kind := "file"
	switch {
	case info.Mode()&os.ModeSymlink != 0: kind = "symlink"
	case info.IsDir(): kind = "directory"
	case !info.Mode().IsRegular(): kind = "special"
	}
	metadata := FileMetadata{Path: filepath.ToSlash(relative), Name: info.Name(), Type: kind, Mode: uint32(info.Mode()), Size: info.Size(), ModTimeUnixNano: info.ModTime().UnixNano()}
	if kind == "symlink" { target, err := os.Readlink(absolute); if err != nil { return FileMetadata{}, err }; metadata.LinkTarget = filepath.ToSlash(target) }
	return metadata, nil
}

func (s *Server) symlink(request Request) (Result, error) {
	relative, absolute, err := s.resolvePath(request.FinalPath); if err != nil { return Result{}, err }
	_, parentRel, _, parentAbs, err := s.resolveFinal(request.FinalPath); if err != nil { return Result{}, err }
	target := strings.TrimSpace(request.LinkTarget)
	if target == "" || strings.IndexByte(target, 0) >= 0 || strings.Contains(target, "\\") || filepath.IsAbs(filepath.FromSlash(target)) { return Result{}, ErrPathDenied }
	targetAbs := filepath.Clean(filepath.Join(parentAbs, filepath.FromSlash(target)))
	if !withinRoot(s.root, targetAbs) { return Result{}, ErrPathDenied }
	if existing, statErr := os.Lstat(absolute); statErr == nil {
		if !request.ReplaceExisting { return Result{}, fmt.Errorf("%w: destination exists", ErrReplaceFailed) }
		if existing.IsDir() { return Result{}, fmt.Errorf("%w: refusing to replace directory with symlink", ErrReplaceFailed) }
		if err := os.Remove(absolute); err != nil { return Result{}, err }
	} else if !os.IsNotExist(statErr) { return Result{}, statErr }
	if err := os.Symlink(filepath.FromSlash(target), absolute); err != nil { return Result{}, err }
	info, err := os.Lstat(absolute); if err != nil { return Result{}, err }
	metadata, err := fileMetadata(relative, absolute, info); if err != nil { return Result{}, err }
	_ = parentRel
	return Result{Metadata: &metadata}, nil
}

func (s *Server) setMetadata(request Request) (Result, error) {
	relative, absolute, err := s.resolvePath(request.FinalPath); if err != nil { return Result{}, err }
	info, err := os.Lstat(absolute); if err != nil { return Result{}, err }
	if info.Mode()&os.ModeSymlink != 0 { return Result{}, fmt.Errorf("%w: symlink metadata mutation is not portable", ErrPathDenied) }
	if request.Mode != 0 { if err := os.Chmod(absolute, os.FileMode(request.Mode&0o7777)); err != nil { return Result{}, err } }
	if request.ModTimeUnixNano != 0 { when := time.Unix(0, request.ModTimeUnixNano); if err := os.Chtimes(absolute, when, when); err != nil { return Result{}, err } }
	info, err = os.Lstat(absolute); if err != nil { return Result{}, err }
	metadata, err := fileMetadata(relative, absolute, info); if err != nil { return Result{}, err }
	return Result{Metadata: &metadata}, nil
}

func (s *Server) prepareTree(request Request) (Result, error) {
	_, parentRel, _, parentAbs, err := s.resolveFinal(request.FinalPath); if err != nil { return Result{}, err }
	_, finalAbs, err := s.resolvePath(request.FinalPath); if err != nil { return Result{}, err }
	replaced := false
	if info, statErr := os.Lstat(finalAbs); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return Result{}, fmt.Errorf("%w: tree destination is not a directory", ErrReplaceFailed) }
		if !request.ReplaceExisting { return Result{}, fmt.Errorf("%w: tree destination exists", ErrReplaceFailed) }
		replaced = true
	} else if !os.IsNotExist(statErr) { return Result{}, statErr }
	mode := os.FileMode(request.Mode & 0o7777); if mode == 0 { mode = 0o755 }
	name, absolute, err := createHiddenDirectory(parentAbs, treeTempPrefix, mode); if err != nil { return Result{}, err }
	relative := name; if parentRel != "" { relative = path.Join(parentRel, name) }
	_ = absolute
	return Result{TempPath: relative, AppliedMode: uint32(mode.Perm()), ReplacedExisting: replaced}, nil
}

func (s *Server) commitTree(request Request) (Result, error) {
	finalRel, finalParentRel, finalName, finalParentAbs, err := s.resolveFinal(request.FinalPath); if err != nil { return Result{}, err }
	tempRel, tempParentRel, tempName, tempParentAbs, err := s.resolveFinal(request.TempPath); if err != nil { return Result{}, err }
	if finalParentRel != tempParentRel || finalParentAbs != tempParentAbs || !strings.HasPrefix(tempName, treeTempPrefix) { return Result{}, ErrPathDenied }
	tempAbs := filepath.Join(tempParentAbs, tempName); finalAbs := filepath.Join(finalParentAbs, finalName)
	tempInfo, err := os.Lstat(tempAbs); if err != nil || !tempInfo.IsDir() || tempInfo.Mode()&os.ModeSymlink != 0 { return Result{}, fmt.Errorf("%w: invalid staged tree", ErrReplaceFailed) }
	if finalInfo, statErr := os.Lstat(finalAbs); os.IsNotExist(statErr) {
		if err := os.Rename(tempAbs, finalAbs); err != nil { return Result{}, fmt.Errorf("%w: atomic tree rename: %v", ErrReplaceFailed, err) }
		return Result{AtomicVisibility: true}, nil
	} else if statErr != nil { return Result{}, statErr
	} else if !request.ReplaceExisting { return Result{}, fmt.Errorf("%w: tree destination exists", ErrReplaceFailed)
	} else if !finalInfo.IsDir() || finalInfo.Mode()&os.ModeSymlink != 0 { return Result{}, fmt.Errorf("%w: tree destination is not a directory", ErrReplaceFailed) }
	backupName, backupAbs, err := reserveHiddenPath(finalParentAbs, treeBackupPrefix); if err != nil { return Result{}, err }
	backupRel := backupName; if finalParentRel != "" { backupRel = path.Join(finalParentRel, backupName) }
	if err := os.Rename(finalAbs, backupAbs); err != nil { return Result{}, fmt.Errorf("%w: stage old tree: %v", ErrReplaceFailed, err) }
	if err := os.Rename(tempAbs, finalAbs); err != nil {
		rollbackErr := os.Rename(backupAbs, finalAbs)
		if rollbackErr != nil { return Result{}, fmt.Errorf("%w: commit tree: %v; rollback: %v", ErrReplaceFailed, err, rollbackErr) }
		return Result{}, fmt.Errorf("%w: commit tree: %v", ErrReplaceFailed, err)
	}
	result := Result{ReplacedExisting: true, AtomicVisibility: false, BackupPath: backupRel}
	if err := os.RemoveAll(backupAbs); err == nil { result.BackupPath = "" }
	_ = tempRel; _ = finalRel
	return result, nil
}

func (s *Server) abortTree(request Request) (Result, error) {
	_, _, name, parentAbs, err := s.resolveFinal(request.TempPath); if err != nil { return Result{}, err }
	if !strings.HasPrefix(name, treeTempPrefix) && !strings.HasPrefix(name, treeBackupPrefix) { return Result{}, ErrPathDenied }
	absolute := filepath.Join(parentAbs, name)
	info, statErr := os.Lstat(absolute); if os.IsNotExist(statErr) { return Result{}, nil }; if statErr != nil { return Result{}, statErr }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return Result{}, ErrPathDenied }
	if err := os.RemoveAll(absolute); err != nil { return Result{}, err }
	return Result{}, nil
}

func (s *Server) prepareReplace(request Request) (Result, error) {
	_, parentRel, finalName, parentAbs, err := s.resolveFinal(request.FinalPath); if err != nil { return Result{}, err }
	finalAbs := filepath.Join(parentAbs, finalName)
	mode := os.FileMode(request.Mode & 0o777); if mode == 0 { mode = 0o644 }
	replaced := false
	if info, statErr := os.Lstat(finalAbs); statErr == nil { if !info.Mode().IsRegular() { return Result{}, fmt.Errorf("%w: destination is not a regular file", ErrReplaceFailed) }; replaced = true; if request.PreserveExistingMode { mode = info.Mode().Perm() } } else if !os.IsNotExist(statErr) { return Result{}, statErr }
	for attempt := 0; attempt < 32; attempt++ {
		name, err := randomName(tempPrefix); if err != nil { return Result{}, err }
		absolute := filepath.Join(parentAbs, name)
		file, err := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if errors.Is(err, os.ErrExist) { continue }; if err != nil { return Result{}, err }
		if err := file.Chmod(mode); err != nil { _ = file.Close(); _ = os.Remove(absolute); return Result{}, err }
		if err := file.Close(); err != nil { _ = os.Remove(absolute); return Result{}, err }
		relative := name; if parentRel != "" { relative = path.Join(parentRel, name) }
		return Result{TempPath: relative, AppliedMode: uint32(mode.Perm()), ReplacedExisting: replaced}, nil
	}
	return Result{}, fmt.Errorf("%w: temporary-name collision limit exceeded", ErrReplaceFailed)
}

func (s *Server) commitReplace(request Request) (Result, error) {
	finalRel, finalParentRel, finalName, finalParentAbs, err := s.resolveFinal(request.FinalPath); if err != nil { return Result{}, err }
	tempRel, tempParentRel, tempName, tempParentAbs, err := s.resolveFinal(request.TempPath); if err != nil { return Result{}, err }
	if finalParentRel != tempParentRel || finalParentAbs != tempParentAbs { return Result{}, fmt.Errorf("%w: temporary and final paths must share one directory", ErrPathDenied) }
	if !strings.HasPrefix(tempName, tempPrefix) { return Result{}, ErrPathDenied }
	tempAbs := filepath.Join(tempParentAbs, tempName); finalAbs := filepath.Join(finalParentAbs, finalName)
	info, err := os.Lstat(tempAbs); if err != nil || !info.Mode().IsRegular() { return Result{}, fmt.Errorf("%w: invalid temporary file", ErrReplaceFailed) }
	if finalInfo, statErr := os.Lstat(finalAbs); statErr == nil { if !finalInfo.Mode().IsRegular() { return Result{}, fmt.Errorf("%w: destination is not a regular file", ErrReplaceFailed) } } else if !os.IsNotExist(statErr) { return Result{}, statErr }
	if err := os.Rename(tempAbs, finalAbs); err != nil { return Result{}, fmt.Errorf("%w: atomic rename %q to %q: %v", ErrReplaceFailed, tempRel, finalRel, err) }
	return Result{}, nil
}

func (s *Server) abortReplace(request Request) (Result, error) {
	_, _, name, parentAbs, err := s.resolveFinal(request.TempPath); if err != nil { return Result{}, err }
	if !strings.HasPrefix(name, tempPrefix) { return Result{}, ErrPathDenied }
	absolute := filepath.Join(parentAbs, name)
	info, statErr := os.Lstat(absolute); if os.IsNotExist(statErr) { return Result{}, nil }; if statErr != nil { return Result{}, statErr }
	if !info.Mode().IsRegular() { return Result{}, ErrPathDenied }
	if err := os.Remove(absolute); err != nil && !os.IsNotExist(err) { return Result{}, err }
	return Result{}, nil
}

func (s *Server) resolvePath(raw string) (string, string, error) {
	relative, _, name, parentAbsolute, err := s.resolveFinal(raw); if err != nil { return "", "", err }
	return relative, filepath.Join(parentAbsolute, name), nil
}

func (s *Server) resolveFinal(raw string) (relative, parentRelative, name, parentAbsolute string, err error) {
	relative, err = cleanRelative(raw); if err != nil { return }
	parentRelative = path.Dir(relative); if parentRelative == "." { parentRelative = "" }
	name = path.Base(relative)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || strings.IndexByte(name, 0) >= 0 { err = fmt.Errorf("%w: invalid final name", ErrPathDenied); return }
	joinedParent := filepath.Join(s.root, filepath.FromSlash(parentRelative))
	parentAbsolute, err = filepath.EvalSymlinks(joinedParent); if err != nil { err = fmt.Errorf("%w: resolve parent: %v", ErrPathDenied, err); return }
	if !withinRoot(s.root, parentAbsolute) { err = ErrPathDenied; return }
	info, statErr := os.Stat(parentAbsolute); if statErr != nil || !info.IsDir() { err = fmt.Errorf("%w: parent is not a directory", ErrPathDenied); return }
	return
}

func cleanRelative(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "/") || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, "\\") { return "", ErrPathDenied }
	for _, component := range strings.Split(raw, "/") { if component == ".." { return "", ErrPathDenied } }
	cleaned := path.Clean(raw); if cleaned == "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") { return "", ErrPathDenied }
	return cleaned, nil
}

func withinRoot(root, target string) bool { relative, err := filepath.Rel(root, target); return err == nil && (relative == "." || relative == "" || (!strings.HasPrefix(relative, "..") && !filepath.IsAbs(relative))) }

func randomName(prefix string) (string, error) { random := make([]byte, 16); if _, err := rand.Read(random); err != nil { return "", err }; return prefix + hex.EncodeToString(random), nil }
func reserveHiddenPath(parent, prefix string) (string, string, error) { for i := 0; i < 32; i++ { name, err := randomName(prefix); if err != nil { return "", "", err }; absolute := filepath.Join(parent, name); if _, err := os.Lstat(absolute); os.IsNotExist(err) { return name, absolute, nil } }; return "", "", fmt.Errorf("%w: hidden path collision limit", ErrReplaceFailed) }
func createHiddenDirectory(parent, prefix string, mode os.FileMode) (string, string, error) { for i := 0; i < 32; i++ { name, err := randomName(prefix); if err != nil { return "", "", err }; absolute := filepath.Join(parent, name); if err := os.Mkdir(absolute, mode); errors.Is(err, os.ErrExist) { continue } else if err != nil { return "", "", err }; _ = os.Chmod(absolute, mode); return name, absolute, nil }; return "", "", fmt.Errorf("%w: directory collision limit", ErrReplaceFailed) }
func minInt(a, b int) int { if a < b { return a }; return b }
