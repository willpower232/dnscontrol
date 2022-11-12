package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/v3/models"
	"github.com/StackExchange/dnscontrol/v3/pkg/credsfile"
	"github.com/StackExchange/dnscontrol/v3/pkg/nameservers"
	"github.com/StackExchange/dnscontrol/v3/pkg/normalize"
	"github.com/StackExchange/dnscontrol/v3/pkg/notifications"
	"github.com/StackExchange/dnscontrol/v3/pkg/printer"
	"github.com/StackExchange/dnscontrol/v3/providers"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
)

var _ = cmd(catMain, func() *cli.Command {
	var args SyncArgs
	return &cli.Command{
		Name:  "sync",
		Usage: "watch for changes and sync to other providers",
		Action: func(ctx *cli.Context) error {
			return exit(Sync(args))
		},
		Flags: args.flags(),
	}
}())

type SyncArgs struct {
	GetDNSConfigArgs
	GetCredentialsArgs
	FilterArgs
	From   string
	Domain string
}

func (args *SyncArgs) flags() []cli.Flag {
	flags := args.GetDNSConfigArgs.flags()
	flags = append(flags, args.GetCredentialsArgs.flags()...)
	flags = append(flags, args.FilterArgs.flags()...)
	flags = append(flags, &cli.StringFlag{
		Name:        "from",
		Destination: &args.From,
		Usage:       `name of provider to watch for changes`,
		Required:    true,
	})
	flags = append(flags, &cli.StringFlag{
		Name:        "domain",
		Destination: &args.Domain,
		Usage:       `domain name to watch for changes`,
		Required:    true,
	})
	return flags
}

func Sync(args SyncArgs) error {
	return doSync(args, printer.DefaultPrinter)
}

func doSync(args SyncArgs, out printer.CLI) error {

	// This is a hack until we have the new printer replacement.
	printer.SkinnyReport = false

	cfg, err := GetDNSConfig(args.GetDNSConfigArgs)
	if err != nil {
		return err
	}

	providerConfigs, err := credsfile.LoadProviderConfigs(args.CredsFile)
	if err != nil {
		return err
	}

	notifier, err := InitializeProviders(cfg, providerConfigs, false)
	if err != nil {
		return err
	}

	errs := normalize.ValidateAndNormalizeConfig(cfg)
	if PrintValidationErrors(errs) {
		return fmt.Errorf("exiting due to validation errors")
	}

	var chosenDomain *models.DomainConfig

	for _, domain := range cfg.Domains {
		if domain.UniqueName == args.Domain {
			chosenDomain = domain
		}
	}

	if chosenDomain == nil {
		return fmt.Errorf("could not find From domain in config")
	}

	out.StartDomain(chosenDomain.UniqueName)

	var from *models.DNSProviderInstance
	var to []*models.DNSProviderInstance

	// guarantee domain exists in all providers and split from and to
	for _, provider := range chosenDomain.DNSProviderInstances {
		if lister, ok := provider.Driver.(providers.ZoneLister); ok {
			zones, err := lister.ListZones()
			if err != nil {
				return err
			}
			if !slices.Contains(zones, chosenDomain.Name) {
				return fmt.Errorf("domain must exist in all providers before syncing")
			}
		}

		if provider.Name == args.From {
			from = provider
		} else {
			to = append(to, provider)
		}
	}

	// identify bad args
	if from == nil || len(to) == 0 {
		return fmt.Errorf("nothing to do, bad arguments?")
	}

	// record nameserver records against the chosen domain
	// so they don't show as deletions
	nsList, err := nameservers.DetermineNameserversForProviders(chosenDomain, chosenDomain.DNSProviderInstances)
	if err != nil {
		return err
	}
	chosenDomain.Nameservers = nsList
	nameservers.AddNSRecords(chosenDomain)

	// state store
	hasChanged := false

	// almost infinite loop to watch for changes and sync them
	// then undo and clear up
	for {
		// duplicate as per preview/push
		// however also very useful here
		dc, err := chosenDomain.Copy()
		if err != nil {
			return err
		}

		// current state of from records
		corrections, err := from.Driver.GetDomainCorrections(dc)
		if err != nil {
			return err
		}

		if !hasChanged {
			// waiting for something to happen

			if len(corrections) != 0 {
				out.Println("change has happened")
				hasChanged = true

				// split hopefully standard format change into usable chunks
				// probably only works because delete isn't batched
				newRecord := strings.Fields(corrections[0].Msg)

				// ttl needs a bit more work to be a real number
				splitTTL := strings.Split(newRecord[4], "=")
				ttl, err := strconv.ParseUint(strings.Trim(splitTTL[1], ","), 10, 64)
				if err != nil {
					return err
				}

				// base fake record
				rc := &models.RecordConfig{
					Type:     newRecord[1],
					Metadata: map[string]string{},
					TTL:      uint32(ttl),
				}

				// set the name of the record
				rc.SetLabel("@", newRecord[2])

				// set the actual content of the record
				rc.SetTarget(newRecord[3])

				// txt values expected here as well
				if newRecord[1] == "TXT" {
					rc.TxtStrings = append(rc.TxtStrings, strings.Replace(newRecord[3], `"`, ``, -1))
				}

				// append the new record to the domain so
				// it doesn't appear as a change
				dc.Records = append(dc.Records, rc)

				// verify our manually created record worked
				corrections, err := from.Driver.GetDomainCorrections(dc)
				if err != nil {
					return err
				}
				if len(corrections) != 0 {
					return fmt.Errorf("creating a fake record did not work")
				}

				out.Println("change stored correctly, uploading change to other providers")

				err = quickApplyConfig(dc, to, out, notifier)
				if err != nil {
					return err
				}

				out.Println("changes applied")
			} else {
				out.Println(fmt.Sprintf("awaiting changes from %s", from.Name))
			}
		} else {
			// waiting to clean up

			if len(corrections) == 0 {
				// ready to reset
				out.Println("changes reverted, resetting to known config")

				err = quickApplyConfig(chosenDomain, to, out, notifier)
				if err != nil {
					return err
				}

				out.Println("revert complete")
				break
			} else {
				out.Println("awaiting revert")
			}
		}

		time.Sleep(3 * time.Second)
	}

	return nil
}

func quickApplyConfig(domain *models.DomainConfig, providers []*models.DNSProviderInstance, out printer.CLI, notifier notifications.Notifier) error {
	for i, provider := range providers {
		corrections, err := provider.Driver.GetDomainCorrections(domain)
		if err != nil {
			return err
		}

		// ordinarily this would be a good thing but we want it
		if len(corrections) != 1 {
			return fmt.Errorf("unable to detect change to apply")
		}

		for _, correction := range corrections {
			out.PrintCorrection(i, correction)

			err = correction.F()

			out.EndCorrection(err)
			if err != nil {
				return err
			}

			notifier.Notify(domain.UniqueName, provider.Name, correction.Msg, err, true)
		}
	}

	return nil
}
