package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ihavespoons/quokka/internal/project"
	"gopkg.in/yaml.v3"
)

// dirName is the on-disk subdirectory under .quokka/ holding rule files.
const dirName = "rules"

// metaSuffix is the file-extension marker that distinguishes quokka metadata
// sidecars from opengrep rule files in the same directory. Using a distinct
// extension means `opengrep scan --config .quokka/rules` won't try to parse
// our metadata as rules.
const metaSuffix = ".zmeta.yaml"

// ruleSuffix is the file-extension of opengrep rule files. Anything in the
// rules dir matching this (and not the metaSuffix) is treated as a rule.
const ruleSuffix = ".yaml"

// Store manages .quokka/rules/<slug>.yaml + <slug>.zmeta.yaml pairs.
type Store struct {
	dir string
}

// NewStore constructs a Store rooted at the given project's .quokka/rules/.
func NewStore(p *project.Project) *Store {
	return &Store{dir: filepath.Join(p.GetQuokkaPath(), dirName)}
}

// Dir returns the on-disk directory holding rule files. Exposed because
// `quokka sast --config <dir>` callers need it to point opengrep at the
// merged rule path.
func (s *Store) Dir() string { return s.dir }

// Add writes a new rule + its metadata. The rule YAML is validated for
// minimal opengrep structure; the metadata is validated for provenance.
// Returns an error if a rule with the same slug already exists — Update
// is the explicit overwrite path.
func (s *Store) Add(slug string, content []byte, meta Meta) error {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return fmt.Errorf("slug is required")
	}
	if !isValidSlug(slug) {
		return fmt.Errorf("slug %q must be lowercase letters, digits, and hyphens only", slug)
	}

	var rf RuleFile
	if err := yaml.Unmarshal(content, &rf); err != nil {
		return fmt.Errorf("parse rule YAML: %w", err)
	}
	if err := rf.ValidateStructure(); err != nil {
		return err
	}

	meta.Slug = slug
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	if err := meta.Validate(); err != nil {
		return err
	}

	if _, err := os.Stat(s.rulePath(slug)); err == nil {
		return fmt.Errorf("rule %q already exists; use Update to overwrite", slug)
	}

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return fmt.Errorf("mkdir rules dir: %w", err)
	}
	if err := os.WriteFile(s.rulePath(slug), content, 0644); err != nil {
		return fmt.Errorf("write rule file: %w", err)
	}
	if err := s.writeMeta(slug, meta); err != nil {
		// Roll back the rule write so partial state doesn't linger.
		_ = os.Remove(s.rulePath(slug))
		return err
	}
	return nil
}

// Update replaces an existing rule's content and/or metadata. Used by the
// rule-judge-agent's Annotate path and by humans tightening a rule.
func (s *Store) Update(slug string, content []byte, meta Meta) error {
	if _, err := s.ReadMeta(slug); err != nil {
		return fmt.Errorf("rule %q not found: %w", slug, err)
	}
	var rf RuleFile
	if err := yaml.Unmarshal(content, &rf); err != nil {
		return fmt.Errorf("parse rule YAML: %w", err)
	}
	if err := rf.ValidateStructure(); err != nil {
		return err
	}
	meta.Slug = slug
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := os.WriteFile(s.rulePath(slug), content, 0644); err != nil {
		return fmt.Errorf("write rule file: %w", err)
	}
	return s.writeMeta(slug, meta)
}

// Remove deletes the rule and its metadata sidecar.
func (s *Store) Remove(slug string) error {
	rPath := s.rulePath(slug)
	if _, err := os.Stat(rPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rule %q not found", slug)
		}
		return err
	}
	if err := os.Remove(rPath); err != nil {
		return fmt.Errorf("remove rule file: %w", err)
	}
	// Metadata absence is non-fatal — older imports may not have one.
	_ = os.Remove(s.metaPath(slug))
	return nil
}

// ReadMeta loads the sidecar metadata for a rule.
func (s *Store) ReadMeta(slug string) (Meta, error) {
	data, err := os.ReadFile(s.metaPath(slug))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("parse meta for %q: %w", slug, err)
	}
	return m, nil
}

// ReadRule loads the raw rule YAML bytes — useful for re-parsing or for
// passing through to opengrep without lossy round-trip.
func (s *Store) ReadRule(slug string) ([]byte, error) {
	return os.ReadFile(s.rulePath(slug))
}

// List returns metadata for every rule on disk. Rules missing a metadata
// sidecar surface with an empty Meta so the caller knows they exist but
// lack provenance — useful for migrations from hand-written rules.
func (s *Store) List() ([]Meta, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var out []Meta
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, metaSuffix) {
			continue
		}
		if !strings.HasSuffix(name, ruleSuffix) {
			continue
		}
		slug := strings.TrimSuffix(name, ruleSuffix)
		m, err := s.ReadMeta(slug)
		if err != nil {
			m = Meta{Slug: slug}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// Annotate updates only the judge-related fields on a rule's metadata.
// The verdict can also flip Disabled on the rule itself (retire = disable);
// because quokka doesn't directly edit the opengrep YAML to add a disabled
// field, we instead store it in metadata and apply it at scan time when
// merging rules into the opengrep --config path.
func (s *Store) Annotate(slug string, verdict Verdict, note string) error {
	if verdict != VerdictUnknown && !IsValidVerdict(verdict) {
		return fmt.Errorf("invalid verdict %q (valid: keep, refine, retire, escalate)", verdict)
	}
	m, err := s.ReadMeta(slug)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	m.Verdict = verdict
	m.VerdictNote = note
	m.LastAuditAt = time.Now().UTC()
	m.Disabled = verdict == VerdictRetire
	return s.writeMeta(slug, m)
}

// EnabledRulePaths returns the paths of all rule files that should be passed
// to opengrep — i.e., rules NOT retired by judge verdict. Stable order.
func (s *Store) EnabledRulePaths() ([]string, error) {
	metas, err := s.List()
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, m := range metas {
		if m.Disabled {
			continue
		}
		paths = append(paths, s.rulePath(m.Slug))
	}
	return paths, nil
}

// ParseRuleIDs reads the rule file for a slug and returns every rule.id
// declared inside. The internal IDs (e.g. "quokka-hand-built-sql") are what
// opengrep emits as `ruleId` in SARIF results, so callers can map findings
// back to the quokka rule slug that produced them.
func (s *Store) ParseRuleIDs(slug string) ([]string, error) {
	data, err := s.ReadRule(slug)
	if err != nil {
		return nil, err
	}
	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rule %q: %w", slug, err)
	}
	out := make([]string, 0, len(rf.Rules))
	for _, r := range rf.Rules {
		if id := strings.TrimSpace(r.ID); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// RuleIDToSlug returns a map from every opengrep rule id (across all
// project-local rule files) to the slug of the rule file that defines it.
// Used by audit code to count triggers per slug.
func (s *Store) RuleIDToSlug() (map[string]string, error) {
	metas, err := s.List()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range metas {
		ids, err := s.ParseRuleIDs(m.Slug)
		if err != nil {
			continue // skip malformed rule files; don't poison the whole map
		}
		for _, id := range ids {
			out[id] = m.Slug
		}
	}
	return out, nil
}

func (s *Store) rulePath(slug string) string { return filepath.Join(s.dir, slug+ruleSuffix) }
func (s *Store) metaPath(slug string) string { return filepath.Join(s.dir, slug+metaSuffix) }

func (s *Store) writeMeta(slug string, m Meta) error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	tmp := s.metaPath(slug) + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return os.Rename(tmp, s.metaPath(slug))
}

func isValidSlug(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s != "" && !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}
