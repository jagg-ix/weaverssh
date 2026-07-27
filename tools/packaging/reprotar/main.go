package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	source := flag.String("source", "", "source directory to archive")
	root := flag.String("root", "", "root directory name inside the archive")
	output := flag.String("output", "", "output .tar.gz path")
	epoch := flag.Int64("epoch", 0, "normalized mtime as Unix epoch seconds")
	flag.Parse()
	if *source == "" || *root == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: reprotar --source DIR --root NAME --output ARCHIVE.tar.gz --epoch SECONDS")
		os.Exit(2)
	}
	if strings.Contains(*root, "/") || strings.Contains(*root, "\\") || *root == "." || *root == ".." || strings.TrimSpace(*root) == "" {
		fmt.Fprintf(os.Stderr, "invalid archive root name: %q\n", *root)
		os.Exit(2)
	}
	if err := writeReproducibleTarGz(*source, *root, *output, time.Unix(*epoch, 0).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeReproducibleTarGz(sourceDir, rootName, output string, mtime time.Time) error {
	var rels []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		rels = append(rels, rel)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(rels)

	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.Name = ""
	gz.Comment = ""
	gz.ModTime = mtime
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, rel := range rels {
		path := filepath.Join(sourceDir, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		name := rootName
		if rel != "." {
			name = rootName + "/" + filepath.ToSlash(rel)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.Uid = 0
		hdr.Gid = 0
		hdr.Uname = "root"
		hdr.Gname = "root"
		hdr.ModTime = mtime
		hdr.AccessTime = time.Time{}
		hdr.ChangeTime = time.Time{}
		hdr.Format = tar.FormatUSTAR
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			hdr.Linkname = link
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header %s: %w", name, err)
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}
