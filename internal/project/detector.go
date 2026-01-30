package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Detector handles tech stack auto-detection
type Detector struct {
	rootPath string
}

// NewDetector creates a new tech stack detector
func NewDetector(rootPath string) *Detector {
	return &Detector{rootPath: rootPath}
}

// DetectAll runs all detection routines and returns a TechStack
func (d *Detector) DetectAll() (*TechStack, error) {
	stack := &TechStack{}

	// Detect languages and frameworks
	if langs, err := d.detectLanguages(); err == nil {
		stack.Languages = langs
	}

	// Detect databases
	if dbs, err := d.detectDatabases(); err == nil {
		stack.Databases = dbs
	}

	// Detect infrastructure
	if infra, err := d.detectInfrastructure(); err == nil {
		stack.Infrastructure = infra
	}

	// Detect auth mechanisms
	if auth, err := d.detectAuth(); err == nil {
		stack.Auth = auth
	}

	return stack, nil
}

// detectLanguages detects programming languages and their frameworks
func (d *Detector) detectLanguages() ([]Language, error) {
	var languages []Language

	// Check for Go
	if lang := d.detectGo(); lang != nil {
		languages = append(languages, *lang)
	}

	// Check for TypeScript/JavaScript
	if lang := d.detectNode(); lang != nil {
		languages = append(languages, *lang)
	}

	// Check for Python
	if lang := d.detectPython(); lang != nil {
		languages = append(languages, *lang)
	}

	// Check for Rust
	if lang := d.detectRust(); lang != nil {
		languages = append(languages, *lang)
	}

	// Check for Java
	if lang := d.detectJava(); lang != nil {
		languages = append(languages, *lang)
	}

	// Check for Ruby
	if lang := d.detectRuby(); lang != nil {
		languages = append(languages, *lang)
	}

	return languages, nil
}

func (d *Detector) detectGo() *Language {
	goModPath := filepath.Join(d.rootPath, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil
	}

	lang := &Language{Name: "go"}

	// Extract Go version
	content := string(data)
	if matches := regexp.MustCompile(`go\s+(\d+\.\d+)`).FindStringSubmatch(content); len(matches) > 1 {
		lang.Version = matches[1]
	}

	// Detect frameworks from go.mod
	frameworks := map[string]string{
		"github.com/gin-gonic/gin":       "gin",
		"github.com/labstack/echo":       "echo",
		"github.com/gofiber/fiber":       "fiber",
		"github.com/gorilla/mux":         "gorilla",
		"github.com/go-chi/chi":          "chi",
		"gorm.io/gorm":                   "gorm",
		"github.com/jmoiron/sqlx":        "sqlx",
		"github.com/graphql-go/graphql":  "graphql",
		"google.golang.org/grpc":         "grpc",
	}

	for pkg, name := range frameworks {
		if strings.Contains(content, pkg) {
			lang.Frameworks = append(lang.Frameworks, name)
		}
	}

	return lang
}

func (d *Detector) detectNode() *Language {
	packagePath := filepath.Join(d.rootPath, "package.json")
	data, err := os.ReadFile(packagePath)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	// Check if TypeScript
	isTS := false
	if _, ok := pkg.DevDependencies["typescript"]; ok {
		isTS = true
	}
	if _, ok := pkg.Dependencies["typescript"]; ok {
		isTS = true
	}
	if _, err := os.Stat(filepath.Join(d.rootPath, "tsconfig.json")); err == nil {
		isTS = true
	}

	lang := &Language{}
	if isTS {
		lang.Name = "typescript"
	} else {
		lang.Name = "javascript"
	}

	// Detect frameworks
	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	frameworks := map[string]string{
		"react":        "react",
		"next":         "nextjs",
		"vue":          "vue",
		"nuxt":         "nuxt",
		"@angular/core": "angular",
		"express":      "express",
		"fastify":      "fastify",
		"koa":          "koa",
		"nest":         "nestjs",
		"@nestjs/core": "nestjs",
	}

	for pkg, name := range frameworks {
		if _, ok := allDeps[pkg]; ok {
			lang.Frameworks = append(lang.Frameworks, name)
		}
	}

	return lang
}

func (d *Detector) detectPython() *Language {
	// Check for various Python indicators
	indicators := []string{"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"}
	found := false
	for _, indicator := range indicators {
		if _, err := os.Stat(filepath.Join(d.rootPath, indicator)); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	lang := &Language{Name: "python"}

	// Check requirements.txt for frameworks
	reqPath := filepath.Join(d.rootPath, "requirements.txt")
	if data, err := os.ReadFile(reqPath); err == nil {
		content := strings.ToLower(string(data))
		frameworks := map[string]string{
			"django":   "django",
			"flask":    "flask",
			"fastapi":  "fastapi",
			"tornado":  "tornado",
			"pyramid":  "pyramid",
			"sqlalchemy": "sqlalchemy",
		}
		for pkg, name := range frameworks {
			if strings.Contains(content, pkg) {
				lang.Frameworks = append(lang.Frameworks, name)
			}
		}
	}

	return lang
}

func (d *Detector) detectRust() *Language {
	cargoPath := filepath.Join(d.rootPath, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return nil
	}

	lang := &Language{Name: "rust"}
	content := string(data)

	frameworks := map[string]string{
		"actix-web": "actix",
		"rocket":    "rocket",
		"axum":      "axum",
		"warp":      "warp",
		"tokio":     "tokio",
		"diesel":    "diesel",
		"sea-orm":   "sea-orm",
	}

	for pkg, name := range frameworks {
		if strings.Contains(content, pkg) {
			lang.Frameworks = append(lang.Frameworks, name)
		}
	}

	return lang
}

func (d *Detector) detectJava() *Language {
	// Check for pom.xml or build.gradle
	pomPath := filepath.Join(d.rootPath, "pom.xml")
	gradlePath := filepath.Join(d.rootPath, "build.gradle")
	gradleKtsPath := filepath.Join(d.rootPath, "build.gradle.kts")

	var content string
	if data, err := os.ReadFile(pomPath); err == nil {
		content = string(data)
	} else if data, err := os.ReadFile(gradlePath); err == nil {
		content = string(data)
	} else if data, err := os.ReadFile(gradleKtsPath); err == nil {
		content = string(data)
	} else {
		return nil
	}

	lang := &Language{Name: "java"}

	frameworks := map[string]string{
		"spring-boot":  "spring-boot",
		"spring-web":   "spring",
		"micronaut":    "micronaut",
		"quarkus":      "quarkus",
		"hibernate":    "hibernate",
		"jakarta.ws.rs": "jax-rs",
	}

	for pkg, name := range frameworks {
		if strings.Contains(content, pkg) {
			lang.Frameworks = append(lang.Frameworks, name)
		}
	}

	return lang
}

func (d *Detector) detectRuby() *Language {
	gemfilePath := filepath.Join(d.rootPath, "Gemfile")
	data, err := os.ReadFile(gemfilePath)
	if err != nil {
		return nil
	}

	lang := &Language{Name: "ruby"}
	content := string(data)

	frameworks := map[string]string{
		"'rails'":   "rails",
		"'sinatra'": "sinatra",
		"'hanami'":  "hanami",
		"'grape'":   "grape",
	}

	for pkg, name := range frameworks {
		if strings.Contains(content, pkg) {
			lang.Frameworks = append(lang.Frameworks, name)
		}
	}

	return lang
}

func (d *Detector) detectDatabases() ([]string, error) {
	var databases []string
	seen := make(map[string]bool)

	// Patterns to search for across various files
	dbPatterns := map[string][]string{
		"postgresql": {"postgres", "postgresql", "pg_", "psycopg"},
		"mysql":      {"mysql", "mariadb"},
		"mongodb":    {"mongodb", "mongoose", "mongo"},
		"redis":      {"redis"},
		"sqlite":     {"sqlite"},
		"elasticsearch": {"elasticsearch", "elastic"},
		"cassandra":  {"cassandra"},
		"dynamodb":   {"dynamodb"},
	}

	// Files to check
	checkFiles := []string{
		"go.mod", "package.json", "requirements.txt", "Cargo.toml",
		"docker-compose.yml", "docker-compose.yaml",
		".env", ".env.example",
	}

	for _, filename := range checkFiles {
		data, err := os.ReadFile(filepath.Join(d.rootPath, filename))
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))

		for db, patterns := range dbPatterns {
			if seen[db] {
				continue
			}
			for _, pattern := range patterns {
				if strings.Contains(content, pattern) {
					databases = append(databases, db)
					seen[db] = true
					break
				}
			}
		}
	}

	return databases, nil
}

func (d *Detector) detectInfrastructure() ([]string, error) {
	var infra []string

	// Check for Docker
	if _, err := os.Stat(filepath.Join(d.rootPath, "Dockerfile")); err == nil {
		infra = append(infra, "docker")
	}
	if _, err := os.Stat(filepath.Join(d.rootPath, "docker-compose.yml")); err == nil {
		if !contains(infra, "docker") {
			infra = append(infra, "docker")
		}
		infra = append(infra, "docker-compose")
	}

	// Check for Kubernetes
	k8sFiles := []string{"k8s/", "kubernetes/", "charts/", "helm/"}
	for _, dir := range k8sFiles {
		if info, err := os.Stat(filepath.Join(d.rootPath, dir)); err == nil && info.IsDir() {
			infra = append(infra, "kubernetes")
			break
		}
	}

	// Check for Terraform
	if matches, _ := filepath.Glob(filepath.Join(d.rootPath, "*.tf")); len(matches) > 0 {
		infra = append(infra, "terraform")
	}

	// Check for CI/CD
	ciConfigs := map[string]string{
		".github/workflows":   "github-actions",
		".gitlab-ci.yml":      "gitlab-ci",
		"Jenkinsfile":         "jenkins",
		".circleci":           "circleci",
		".travis.yml":         "travis",
		"azure-pipelines.yml": "azure-devops",
	}

	for path, name := range ciConfigs {
		if _, err := os.Stat(filepath.Join(d.rootPath, path)); err == nil {
			infra = append(infra, name)
		}
	}

	return infra, nil
}

func (d *Detector) detectAuth() ([]string, error) {
	var auth []string
	seen := make(map[string]bool)

	authPatterns := map[string][]string{
		"jwt":     {"jwt", "jsonwebtoken", "jose"},
		"oauth2":  {"oauth2", "oauth", "oidc", "openid"},
		"saml":    {"saml"},
		"ldap":    {"ldap"},
		"basic":   {"basic-auth", "basicauth"},
		"api-key": {"api-key", "apikey", "x-api-key"},
		"session": {"express-session", "session-store"},
	}

	// Search common files
	err := filepath.Walk(d.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip hidden dirs and common ignore patterns
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".zrok" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only check certain file types
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".js" && ext != ".ts" && ext != ".py" && ext != ".java" && ext != ".rb" && ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := strings.ToLower(string(data))

		for authType, patterns := range authPatterns {
			if seen[authType] {
				continue
			}
			for _, pattern := range patterns {
				if strings.Contains(content, pattern) {
					auth = append(auth, authType)
					seen[authType] = true
					break
				}
			}
		}

		return nil
	})

	if err != nil {
		return auth, err
	}

	return auth, nil
}

// DetectSensitiveAreas identifies potentially sensitive code areas
func (d *Detector) DetectSensitiveAreas() ([]SensitiveArea, error) {
	var areas []SensitiveArea
	seen := make(map[string]bool)

	sensitivePatterns := map[string]string{
		"auth":     "Authentication logic",
		"login":    "Login handling",
		"admin":    "Administrative functionality",
		"payment":  "Payment processing",
		"crypto":   "Cryptographic operations",
		"secret":   "Secret management",
		"password": "Password handling",
		"token":    "Token management",
		"api":      "API endpoints",
		"webhook":  "Webhook handlers",
	}

	err := filepath.Walk(d.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".zrok" {
				return filepath.SkipDir
			}

			for pattern, reason := range sensitivePatterns {
				if strings.Contains(strings.ToLower(name), pattern) {
					relPath, _ := filepath.Rel(d.rootPath, path)
					if !seen[relPath] {
						areas = append(areas, SensitiveArea{
							Path:   relPath + "/",
							Reason: reason,
						})
						seen[relPath] = true
					}
					break
				}
			}
		}

		return nil
	})

	return areas, err
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
