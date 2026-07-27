//go:build linux || darwin

// Package vfsmount mounts the weaverssh vfs:// namespace as a real filesystem
// via FUSE, translating kernel filesystem operations into 9P client calls. The
// same code drives macFUSE on macOS and libfuse/kernel-FUSE on Linux because
// go-fuse speaks the FUSE wire protocol directly. A FUSE mount is also the
// bridge to libvirt: point a domain's <filesystem> source at the mountpoint and
// a guest sees the namespace over virtio-9p.
//
// I/O model (sshfs-style): files are read and written positionally against a
// persistent open fid — a single read never loads the whole file — and the
// kernel's own read-ahead drives large sequential transfers. Metadata (stat /
// directory listings) is served from a short-TTL cache and the kernel's
// entry/attr timeouts, with the cache invalidated on local mutations.
package vfsmount

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"weaverssh/internal/p9client"
	"weaverssh/internal/vfs"
)

// Options controls how the namespace is mounted.
type Options struct {
	ReadOnly   bool
	AllowOther bool           // allow users other than the mounter (needs user_allow_other)
	VolumeName string         // macOS Finder volume label
	Debug      bool           // log FUSE protocol traffic
	CacheTTL   time.Duration  // metadata cache lifetime; 0 uses a default, <0 disables
	View       vfs.ViewConfig // optional hide/rename projection applied to visible FUSE paths
}

const defaultCacheTTL = time.Second

// Mount attaches the vfs:// namespace served via c at mountpoint and returns the
// running FUSE server. Call server.Wait() to block and server.Unmount() to
// detach. The caller owns c and should close it after the server returns.
func Mount(mountpoint string, c *p9client.Client, opts Options) (*fuse.Server, error) {
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = defaultCacheTTL
	}
	view := opts.View
	if _, err := view.Normalize(); err != nil {
		return nil, err
	}
	root := &node{
		client:   c,
		rel:      "",
		viewRel:  "",
		isDir:    true,
		readOnly: opts.ReadOnly,
		cache:    &attrCache{ttl: ttl, stat: map[string]statEntry{}, list: map[string]listEntry{}},
		view:     view,
	}
	mountOpts := fuse.MountOptions{
		FsName:   "weaverssh-vfs",
		Name:     "weaverssh",
		Debug:    opts.Debug,
		MaxWrite: 1 << 20, // larger writes => fewer round-trips
	}
	if opts.AllowOther {
		mountOpts.AllowOther = true
	}
	if opts.VolumeName != "" {
		mountOpts.Options = append(mountOpts.Options, "volname="+opts.VolumeName)
	}
	entryTTL := ttl
	if entryTTL < 0 {
		entryTTL = 0
	}
	return fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: mountOpts,
		EntryTimeout: &entryTTL,
		AttrTimeout:  &entryTTL,
	})
}

// node is one inode in the mounted tree: a 9P client plus this node's
// namespace-relative path, sharing one metadata cache across the tree.
type node struct {
	fs.Inode
	client   *p9client.Client
	rel      string // source namespace path sent to 9P
	viewRel  string // visible path exposed by the mounted view
	isDir    bool
	readOnly bool
	cache    *attrCache
	view     vfs.ViewConfig
}

var (
	_ fs.NodeLookuper  = (*node)(nil)
	_ fs.NodeReaddirer = (*node)(nil)
	_ fs.NodeGetattrer = (*node)(nil)
	_ fs.NodeOpener    = (*node)(nil)
	_ fs.NodeReader    = (*node)(nil)
	_ fs.NodeWriter    = (*node)(nil)
	_ fs.NodeCreater   = (*node)(nil)
	_ fs.NodeMkdirer   = (*node)(nil)
	_ fs.NodeUnlinker  = (*node)(nil)
	_ fs.NodeRmdirer   = (*node)(nil)
	_ fs.NodeFlusher   = (*node)(nil)
	_ fs.NodeReleaser  = (*node)(nil)
)

func (n *node) child(name string) string {
	return joinRel(n.rel, name)
}

func (n *node) childView(name string) string {
	return joinRel(n.viewPath(), name)
}

func (n *node) viewPath() string {
	if n.viewRel != "" || n.rel == "" {
		return n.viewRel
	}
	// Older unit tests construct nodes directly without setting viewRel. Preserve
	// those source-path nodes as identity-view nodes.
	return n.rel
}

func (n *node) sourceForView(viewRel string) (string, bool, error) {
	return n.view.SourcePath(viewRel)
}

func (n *node) newChild(sourceRel, viewRel string, isDir bool) *node {
	return &node{client: n.client, rel: sourceRel, viewRel: viewRel, isDir: isDir, readOnly: n.readOnly, cache: n.cache, view: n.view}
}

func fileMode(isDir bool) uint32 {
	if isDir {
		return fuse.S_IFDIR | 0o755
	}
	return fuse.S_IFREG | 0o644
}

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	child, st, errno := n.lookupChild(name)
	if errno != 0 {
		return nil, errno
	}
	out.Mode = fileMode(st.IsDir)
	out.Size = st.Size
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fileMode(st.IsDir)}), 0
}

func (n *node) lookupChild(name string) (*node, p9client.DirEntry, syscall.Errno) {
	viewRel := n.childView(name)
	rel, hidden, err := n.sourceForView(viewRel)
	if err != nil || hidden {
		return nil, p9client.DirEntry{}, syscall.ENOENT
	}
	st, err := n.statCached(rel)
	if err != nil {
		return nil, p9client.DirEntry{}, syscall.ENOENT
	}
	return n.newChild(rel, viewRel, st.IsDir), st, 0
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := n.listCached(n.rel)
	if err != nil {
		return nil, syscall.EIO
	}
	mapped, err := n.view.ListEntries(n.rel, n.viewPath(), entries)
	if err != nil {
		return nil, syscall.EIO
	}
	list := make([]fuse.DirEntry, 0, len(mapped))
	for _, e := range mapped {
		list = append(list, fuse.DirEntry{Name: e.Entry.Name, Mode: fileMode(e.Entry.IsDir)})
	}
	return fs.NewListDirStream(list), 0
}

func (n *node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	st, err := n.statCached(n.rel)
	if err != nil {
		return syscall.EIO
	}
	out.Mode = fileMode(st.IsDir)
	out.Size = st.Size
	return 0
}

// handle wraps an open 9P fid for positional reads/writes.
type handle struct {
	node *node
	file *p9client.File
}

func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	mode, write := openMode(flags)
	if n.readOnly && write {
		return nil, 0, syscall.EROFS
	}
	f, err := n.client.OpenFile(n.rel, mode)
	if err != nil {
		return nil, 0, syscall.EIO
	}
	if write {
		n.cache.invalidate(n.rel)
	}
	return &handle{node: n, file: f}, 0, 0
}

func (n *node) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return nil, syscall.EBADF
	}
	got, err := h.file.ReadAt(dest, off)
	if err != nil {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest[:got]), 0
}

func (n *node) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if n.readOnly {
		return 0, syscall.EROFS
	}
	h, ok := f.(*handle)
	if !ok {
		return 0, syscall.EBADF
	}
	wrote, err := h.file.WriteAt(data, off)
	if err != nil {
		return uint32(wrote), syscall.EIO
	}
	n.cache.invalidate(n.rel) // size/mtime changed
	return uint32(wrote), 0
}

func (n *node) Flush(ctx context.Context, f fs.FileHandle) syscall.Errno {
	return 0 // writes are sent through immediately
}

func (n *node) Release(ctx context.Context, f fs.FileHandle) syscall.Errno {
	if h, ok := f.(*handle); ok && h.file != nil {
		_ = h.file.Close()
	}
	return 0
}

func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	child, f, errno := n.createFile(name)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG})
	out.Mode = fileMode(false)
	out.Size = 0
	return inode, &handle{node: child, file: f}, 0, 0
}

func (n *node) createFile(name string) (*node, *p9client.File, syscall.Errno) {
	if n.readOnly {
		return nil, nil, syscall.EROFS
	}
	viewRel := n.childView(name)
	rel, hidden, err := n.sourceForView(viewRel)
	if err != nil || hidden {
		return nil, nil, syscall.EACCES
	}
	f, err := n.client.CreateFile(rel, 0o644)
	if err != nil {
		return nil, nil, syscall.EIO
	}
	n.cache.invalidate(rel)
	return n.newChild(rel, viewRel, false), f, 0
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.readOnly {
		return nil, syscall.EROFS
	}
	viewRel := n.childView(name)
	rel, hidden, err := n.sourceForView(viewRel)
	if err != nil || hidden {
		return nil, syscall.EACCES
	}
	if err := n.client.Mkdir(rel); err != nil {
		return nil, syscall.EIO
	}
	n.cache.invalidate(rel)
	child := n.newChild(rel, viewRel, true)
	out.Mode = fileMode(true)
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFDIR}), 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno { return n.remove(name) }
func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno  { return n.remove(name) }

func (n *node) remove(name string) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	viewRel := n.childView(name)
	rel, hidden, err := n.sourceForView(viewRel)
	if err != nil || hidden {
		return syscall.EACCES
	}
	if err := n.client.Remove(rel); err != nil {
		return syscall.EIO
	}
	n.cache.invalidate(rel)
	return 0
}

// statCached / listCached front the 9P client with the shared TTL cache.
func (n *node) statCached(rel string) (p9client.DirEntry, error) {
	if e, ok := n.cache.getStat(rel); ok {
		return e, nil
	}
	e, err := n.client.Stat(rel)
	if err != nil {
		return p9client.DirEntry{}, err
	}
	n.cache.putStat(rel, e)
	return e, nil
}

func (n *node) listCached(rel string) ([]p9client.DirEntry, error) {
	if es, ok := n.cache.getList(rel); ok {
		return es, nil
	}
	es, err := n.client.List(rel)
	if err != nil {
		return nil, err
	}
	n.cache.putList(rel, es)
	// Populate per-entry stat cache so the readdir+stat storm that follows a
	// listing is served without extra round-trips.
	for _, e := range es {
		n.cache.putStat(joinRel(rel, e.Name), e)
	}
	return es, nil
}

// openMode maps kernel open flags to a 9P open mode and whether write access is
// requested.
func openMode(flags uint32) (mode uint8, write bool) {
	switch flags & uint32(syscall.O_ACCMODE) {
	case uint32(syscall.O_WRONLY), uint32(syscall.O_RDWR):
		write = true
	}
	if flags&uint32(syscall.O_TRUNC) != 0 {
		write = true
	}
	if write {
		mode = p9client.OWRITE
	} else {
		mode = p9client.OREAD
	}
	if flags&uint32(syscall.O_TRUNC) != 0 {
		mode |= p9client.OTRUNC
	}
	return mode, write
}

func joinRel(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func parentRel(rel string) string {
	for i := len(rel) - 1; i >= 0; i-- {
		if rel[i] == '/' {
			return rel[:i]
		}
	}
	return ""
}

// --- metadata cache --------------------------------------------------------

type statEntry struct {
	val p9client.DirEntry
	exp time.Time
}

type listEntry struct {
	val []p9client.DirEntry
	exp time.Time
}

type attrCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	stat map[string]statEntry
	list map[string]listEntry
}

func (c *attrCache) enabled() bool { return c != nil && c.ttl > 0 }

func (c *attrCache) getStat(rel string) (p9client.DirEntry, bool) {
	if !c.enabled() {
		return p9client.DirEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.stat[rel]
	if !ok || time.Now().After(e.exp) {
		return p9client.DirEntry{}, false
	}
	return e.val, true
}

func (c *attrCache) putStat(rel string, v p9client.DirEntry) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	c.stat[rel] = statEntry{val: v, exp: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *attrCache) getList(rel string) ([]p9client.DirEntry, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.list[rel]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.val, true
}

func (c *attrCache) putList(rel string, v []p9client.DirEntry) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	c.list[rel] = listEntry{val: v, exp: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// invalidate drops the cached stat for rel and the listing of its parent (and
// of rel itself, if it was a directory), so mutations are immediately visible.
func (c *attrCache) invalidate(rel string) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	delete(c.stat, rel)
	delete(c.list, rel)
	delete(c.list, parentRel(rel))
	c.mu.Unlock()
}
