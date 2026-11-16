package utils

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	rootutils "github.com/Method-Security/osintscan/utils"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	assettypes "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// buildAmassConfig creates and configures an Amass v4 config object with optimized performance settings.
func buildAmassConfig(cfg dnsfern.DiscoverDnsSubdomainPassiveConfig, log svc1log.Logger) *config.Config {
	amassCfg := config.NewConfig()
	amassCfg.Passive = true
	amassCfg.AddDomain(NormalizeDomain(cfg.Domain))
	amassCfg.Recursive = false
	amassCfg.Verbose = false
	resolvers := make([]string, 0, len(cfg.DnsResolvers))
	for _, resolver := range cfg.DnsResolvers {
		resolvers = append(resolvers, rootutils.NormalizeDNSAddress(resolver))
	}
	amassCfg.AddResolvers(resolvers...)

	// Configure parallelism and performance
	// Increase concurrent DNS queries for faster resolution
	amassCfg.MaxDNSQueries = cfg.MaxDnsQueries // Default is much lower

	// Increase queries per second per resolver for passive mode
	// Passive mode doesn't do active DNS queries, but this helps with validation
	amassCfg.ResolversQPS = cfg.MaxResolversQps // Queries per second per resolver

	log.Info("Amass performance settings",
		svc1log.SafeParam("max_dns_queries", amassCfg.MaxDNSQueries),
		svc1log.SafeParam("resolvers", len(amassCfg.Resolvers)),
		svc1log.SafeParam("qps_per_resolver", amassCfg.ResolversQPS))

	return amassCfg
}

// GetSubdomainsPassiveWithAmass uses Amass v4 to passively enumerate the target domain and its subdomains in an isolated local graph.
func GetSubdomainsPassiveWithAmass(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg.Domain = NormalizeDomain(cfg.Domain)

	log.Info("Configuring Amass v4 for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
	)

	// Build amass v4 config
	amassCfg := buildAmassConfig(cfg, log)
	if len(amassCfg.Domains()) != 1 {
		return nil, fmt.Errorf("invalid Amass target domain: %q", cfg.Domain)
	}

	// LocalSystem otherwise uses a shared SQLite database across concurrent scans.
	dir, err := os.MkdirTemp("", "osintscan-amass-*")
	if err != nil {
		return nil, fmt.Errorf("create Amass output directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Warn("Failed to remove Amass output directory", svc1log.SafeParam("error", err.Error()))
		}
	}()
	amassCfg.Dir = dir

	// Create a local system for Amass v4
	sys, err := systems.NewLocalSystem(amassCfg)
	if err != nil {
		log.Warn("Failed to create Amass v4 system",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}
	defer func() {
		if err := sys.Shutdown(); err != nil {
			log.Warn("Failed to shut down Amass system", svc1log.SafeParam("error", err.Error()))
		}
	}()

	// Load all available data sources
	allSources := datasrcs.GetAllSources(sys)
	if err := sys.SetDataSources(allSources); err != nil {
		log.Warn("Failed to set data sources",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Log the number of data sources being used
	dataSources := sys.DataSources()
	log.Info("Amass data sources initialized",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("source_count", len(dataSources)))

	// Get the graph database from the system.
	graphs := sys.GraphDatabases()
	if len(graphs) == 0 {
		log.Warn("No graph database available",
			svc1log.SafeParam("domain", cfg.Domain))
		return nil, fmt.Errorf("no Amass graph database available")
	}
	graph := graphs[0]

	// Create and run enumeration
	e := enum.NewEnumeration(amassCfg, sys, graph)

	// Stop and join the progress reader before shutting down the system.
	progressCtx, cancelProgress := context.WithCancel(ctx)
	progressDone := make(chan struct{})
	defer func() {
		cancelProgress()
		<-progressDone
	}()
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		previousDomains := make(map[string]struct{})

		for {
			select {
			case <-progressCtx.Done():
				return
			case <-ticker.C:
				// Query the graph database for current count
				if assets, err := graph.DB.FindByType(oam.FQDN, amassCfg.CollectionStartTime); err == nil {
					currentDomains := make(map[string]struct{})
					for _, name := range scopedAmassSubdomains(assets, cfg.Domain) {
						currentDomains[name] = struct{}{}
					}

					// Find new domains since last check
					var newDomains []string
					for domainName := range currentDomains {
						if _, exists := previousDomains[domainName]; !exists {
							newDomains = append(newDomains, domainName)
						}
					}

					currentCount := len(currentDomains)
					delta := len(newDomains)
					log.Info("Enumeration progress",
						svc1log.SafeParam("domain", cfg.Domain),
						svc1log.SafeParam("subdomains_found_so_far", currentCount),
						svc1log.SafeParam("new_since_last_check", delta))

					// Print each new domain found
					for _, newDomain := range newDomains {
						log.Debug("Domain Found", svc1log.SafeParam("domain.FQDN", newDomain))
					}

					previousDomains = currentDomains
				}
			}
		}
	}()

	if err := e.Start(ctx); err != nil {
		log.Warn("Amass v4 enumeration failed",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Query the graph database for all discovered FQDN assets.
	// Use the collection start time to get only newly discovered assets
	assets, err := graph.DB.FindByType(oam.FQDN, amassCfg.CollectionStartTime)
	if err != nil {
		log.Warn("Failed to query graph database",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	log.Info("Retrieved assets from graph database",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("asset_count", len(assets)))

	subdomains := scopedAmassSubdomains(assets, cfg.Domain)

	log.Info("Amass enumeration completed (v4)",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, nil
}

// The graph also contains related infrastructure outside the requested domain.
func scopedAmassSubdomains(assets []*assettypes.Asset, target string) []string {
	found := make(map[string]struct{})
	for _, asset := range assets {
		if asset == nil {
			continue
		}
		if fqdn, ok := asset.Asset.(domain.FQDN); ok && IsDomainInScope(fqdn.Name, target) {
			found[NormalizeDomain(fqdn.Name)] = struct{}{}
		}
	}
	subdomains := make([]string, 0, len(found))
	for name := range found {
		subdomains = append(subdomains, name)
	}
	sort.Strings(subdomains)
	return subdomains
}
