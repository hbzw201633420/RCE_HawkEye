package dict

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type DictEntry struct {
	Word        string `json:"word"`
	HitCount    int    `json:"hit_count"`
	MissCount   int    `json:"miss_count"`
	LastUsed    int64  `json:"last_used"`
	LastHit     int64  `json:"last_hit"`
	IsArchived  bool   `json:"is_archived"`
	Priority    int    `json:"priority"`
	Weight      int    `json:"weight"`
	Status200Count int `json:"status_200_count"`
	StatusOtherCount int `json:"status_other_count"`
}

type SmartDict struct {
	mu              sync.RWMutex
	entries         map[string]*DictEntry
	archiveEntries  map[string]*DictEntry
	archiveThreshold int
	dictType        string
	dataFile        string
	backupDir       string
}

type SmartDictOption func(*SmartDict)

func WithArchiveThreshold(threshold int) SmartDictOption {
	return func(d *SmartDict) {
		d.archiveThreshold = threshold
	}
}

func WithDictType(dictType string) SmartDictOption {
	return func(d *SmartDict) {
		d.dictType = dictType
	}
}

func WithDataFile(file string) SmartDictOption {
	return func(d *SmartDict) {
		d.dataFile = file
	}
}

func WithBackupDir(dir string) SmartDictOption {
	return func(d *SmartDict) {
		d.backupDir = dir
	}
}

func NewSmartDict(opts ...SmartDictOption) *SmartDict {
	d := &SmartDict{
		entries:          make(map[string]*DictEntry),
		archiveEntries:   make(map[string]*DictEntry),
		archiveThreshold: 30,
		dictType:         "dir",
		dataFile:         "",
		backupDir:        "./data/dict",
	}

	for _, opt := range opts {
		opt(d)
	}

	if d.dataFile != "" {
		d.Load()
	}

	return d
}

func (d *SmartDict) AddWord(word string, priority int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.entries[word]; !exists {
		d.entries[word] = &DictEntry{
			Word:     word,
			Priority: priority,
			LastUsed: time.Now().Unix(),
		}
	}
}

func (d *SmartDict) RecordHit(word string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.entries[word]; exists {
		entry.HitCount++
		entry.LastHit = time.Now().Unix()
		entry.LastUsed = time.Now().Unix()
	} else {
		d.entries[word] = &DictEntry{
			Word:     word,
			HitCount: 1,
			LastHit:  time.Now().Unix(),
			LastUsed: time.Now().Unix(),
		}
	}

	d.checkArchive()
}

func (d *SmartDict) RecordMiss(word string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.entries[word]; exists {
		entry.MissCount++
		entry.LastUsed = time.Now().Unix()
	} else {
		d.entries[word] = &DictEntry{
			Word:      word,
			MissCount: 1,
			LastUsed:  time.Now().Unix(),
		}
	}

	d.checkArchive()
}

func (d *SmartDict) RecordResult(word string, statusCode int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.entries[word]; exists {
		if statusCode == 200 {
			entry.Status200Count++
			entry.Weight += 4
			entry.HitCount++
			entry.LastHit = time.Now().Unix()
		} else if statusCode != 404 {
			entry.StatusOtherCount++
			entry.Weight += 1
		} else {
			entry.MissCount++
		}
		entry.LastUsed = time.Now().Unix()
	} else {
		entry := &DictEntry{
			Word:     word,
			LastUsed: time.Now().Unix(),
		}
		if statusCode == 200 {
			entry.Status200Count = 1
			entry.Weight = 4
			entry.HitCount = 1
			entry.LastHit = time.Now().Unix()
		} else if statusCode != 404 {
			entry.StatusOtherCount = 1
			entry.Weight = 1
		} else {
			entry.MissCount = 1
		}
		d.entries[word] = entry
	}

	d.checkArchive()
}

func (d *SmartDict) RecordParamResult(paramName string, statusCode int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.entries[paramName]; exists {
		if statusCode == 200 {
			entry.Status200Count++
			entry.Weight += 4
			entry.HitCount++
			entry.LastHit = time.Now().Unix()
		} else if statusCode != 404 {
			entry.StatusOtherCount++
			entry.Weight += 1
		} else {
			entry.MissCount++
		}
		entry.LastUsed = time.Now().Unix()
	} else {
		entry := &DictEntry{
			Word:     paramName,
			LastUsed: time.Now().Unix(),
		}
		if statusCode == 200 {
			entry.Status200Count = 1
			entry.Weight = 4
			entry.HitCount = 1
			entry.LastHit = time.Now().Unix()
		} else if statusCode != 404 {
			entry.StatusOtherCount = 1
			entry.Weight = 1
		} else {
			entry.MissCount = 1
		}
		d.entries[paramName] = entry
	}

	d.checkArchive()
}

func (d *SmartDict) checkArchive() {
	for word, entry := range d.entries {
		if !entry.IsArchived && entry.MissCount >= d.archiveThreshold && entry.HitCount == 0 {
			entry.IsArchived = true
			d.archiveEntries[word] = entry
			delete(d.entries, word)
		}
	}
}

func (d *SmartDict) GetSortedWords() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	words := make([]string, 0, len(d.entries))
	for _, entry := range d.entries {
		words = append(words, entry.Word)
	}

	sort.Slice(words, func(i, j int) bool {
		ei, ej := d.entries[words[i]], d.entries[words[j]]
		if ei.Weight != ej.Weight {
			return ei.Weight > ej.Weight
		}
		if ei.HitCount != ej.HitCount {
			return ei.HitCount > ej.HitCount
		}
		if ei.Priority != ej.Priority {
			return ei.Priority > ej.Priority
		}
		return ei.LastHit > ej.LastHit
	})

	return words
}

func (d *SmartDict) GetTopWords(limit int) []string {
	words := d.GetSortedWords()
	if len(words) <= limit {
		return words
	}
	return words[:limit]
}

func (d *SmartDict) ResetMissCount(word string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.entries[word]; exists {
		entry.MissCount = 0
	}
}

func (d *SmartDict) ResetAllMissCounts() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, entry := range d.entries {
		entry.MissCount = 0
	}
}

func (d *SmartDict) RestoreFromArchive(word string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry, exists := d.archiveEntries[word]; exists {
		entry.IsArchived = false
		entry.MissCount = 0
		d.entries[word] = entry
		delete(d.archiveEntries, word)
		return true
	}
	return false
}

func (d *SmartDict) GetStatistics() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	totalHits := 0
	totalMisses := 0
	for _, entry := range d.entries {
		totalHits += entry.HitCount
		totalMisses += entry.MissCount
	}

	return map[string]interface{}{
		"active_entries":   len(d.entries),
		"archived_entries": len(d.archiveEntries),
		"total_hits":       totalHits,
		"total_misses":     totalMisses,
		"archive_threshold": d.archiveThreshold,
	}
}

func (d *SmartDict) Save() error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.dataFile == "" {
		return nil
	}

	data := struct {
		Entries         map[string]*DictEntry `json:"entries"`
		ArchiveEntries  map[string]*DictEntry `json:"archive_entries"`
		ArchiveThreshold int                  `json:"archive_threshold"`
		DictType        string                `json:"dict_type"`
		SavedAt         int64                 `json:"saved_at"`
	}{
		Entries:         d.entries,
		ArchiveEntries:  d.archiveEntries,
		ArchiveThreshold: d.archiveThreshold,
		DictType:        d.dictType,
		SavedAt:         time.Now().Unix(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(d.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if d.backupDir != "" {
		d.createBackup()
	}

	return os.WriteFile(d.dataFile, jsonData, 0644)
}

func (d *SmartDict) createBackup() {
	if d.dataFile == "" || d.backupDir == "" {
		return
	}

	if _, err := os.Stat(d.dataFile); os.IsNotExist(err) {
		return
	}

	backupFile := filepath.Join(d.backupDir, d.dictType+"_dict_"+time.Now().Format("20060102")+".json")
	os.MkdirAll(d.backupDir, 0755)
	
	input, err := os.ReadFile(d.dataFile)
	if err != nil {
		return
	}
	os.WriteFile(backupFile, input, 0644)
}

func (d *SmartDict) Load() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dataFile == "" {
		return nil
	}

	data, err := os.ReadFile(d.dataFile)
	if err != nil {
		return err
	}

	var savedData struct {
		Entries         map[string]*DictEntry `json:"entries"`
		ArchiveEntries  map[string]*DictEntry `json:"archive_entries"`
		ArchiveThreshold int                  `json:"archive_threshold"`
		DictType        string                `json:"dict_type"`
	}

	if err := json.Unmarshal(data, &savedData); err != nil {
		return err
	}

	d.entries = savedData.Entries
	if d.entries == nil {
		d.entries = make(map[string]*DictEntry)
	}
	d.archiveEntries = savedData.ArchiveEntries
	if d.archiveEntries == nil {
		d.archiveEntries = make(map[string]*DictEntry)
	}
	if savedData.ArchiveThreshold > 0 {
		d.archiveThreshold = savedData.ArchiveThreshold
	}

	return nil
}

func (d *SmartDict) SetArchiveThreshold(threshold int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.archiveThreshold = threshold
}

func (d *SmartDict) GetArchiveThreshold() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.archiveThreshold
}

func (d *SmartDict) GetArchivedWords() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	words := make([]string, 0, len(d.archiveEntries))
	for word := range d.archiveEntries {
		words = append(words, word)
	}
	return words
}

func (d *SmartDict) MergeWords(words []string, priority int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, word := range words {
		if _, exists := d.entries[word]; !exists {
			d.entries[word] = &DictEntry{
				Word:     word,
				Priority: priority,
				LastUsed: time.Now().Unix(),
			}
		}
	}
}

func (d *SmartDict) GetHitRate(word string) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if entry, exists := d.entries[word]; exists {
		total := entry.HitCount + entry.MissCount
		if total == 0 {
			return 0
		}
		return float64(entry.HitCount) / float64(total)
	}
	return 0
}
