package storageadapter

import (
	"bytes"
	"context"
	"errors"
)

type MigrateOptions struct {
	Prefix    []byte
	BatchSize int
	Replace   bool
}

type MigrateReport struct {
	SourceEngine      string `json:"source_engine"`
	DestinationEngine string `json:"destination_engine"`
	Entries           uint64 `json:"entries"`
	Bytes             uint64 `json:"bytes"`
	Batches           uint64 `json:"batches"`
}

func Migrate(ctx context.Context, source, destination Store, options MigrateOptions) (MigrateReport, error) {
	if source == nil || destination == nil {
		return MigrateReport{}, errors.New("storageadapter: source and destination are required")
	}
	if options.BatchSize <= 0 {
		options.BatchSize = 256
	}
	if options.BatchSize > 10000 {
		return MigrateReport{}, errors.New("storageadapter: migration batch size exceeds 10000")
	}
	report := MigrateReport{SourceEngine: source.Name(), DestinationEngine: destination.Name()}
	var after []byte
	for {
		select {
		case <-ctxOrBackground(ctx).Done():
			return report, ctxOrBackground(ctx).Err()
		default:
		}
		entries, err := source.Scan(ctx, ScanOptions{Prefix: options.Prefix, After: after, Limit: options.BatchSize})
		if err != nil {
			return report, err
		}
		if len(entries) == 0 {
			return report, nil
		}
		if err := destination.Update(ctx, func(tx Tx) error {
			for _, entry := range entries {
				if !options.Replace {
					if _, err := tx.Get(entry.Key); err == nil {
						return ErrConflict
					} else if !errors.Is(err, ErrNotFound) {
						return err
					}
				}
				if err := tx.Put(entry.Key, entry.Value); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return report, err
		}
		report.Batches++
		for _, entry := range entries {
			report.Entries++
			report.Bytes += uint64(len(entry.Key) + len(entry.Value))
		}
		after = append(after[:0], entries[len(entries)-1].Key...)
		if len(entries) < options.BatchSize {
			return report, nil
		}
		if len(options.Prefix) > 0 && !bytes.HasPrefix(after, options.Prefix) {
			return report, nil
		}
	}
}
