package firewall

import (
	"context"
	"fmt"
	"net"
)

type SetBackend interface {
	Ensure(context.Context) error
	Block(context.Context, net.IP, int) error
	Unblock(context.Context, net.IP) error
}

type RuleManager interface {
	Ensure(context.Context) error
}

// ManagedBackend keeps the static firewall rules attached while delegating
// timed membership to ipset.
type ManagedBackend struct {
	Sets         SetBackend
	Prerequisite RuleManager
	Rules        RuleManager
}

func NewManagedBackend(sets SetBackend, prerequisite, rules RuleManager) (*ManagedBackend, error) {
	if sets == nil || rules == nil {
		return nil, fmt.Errorf("ipset backend and firewall rule manager are required")
	}

	return &ManagedBackend{Sets: sets, Prerequisite: prerequisite, Rules: rules}, nil
}

func (b *ManagedBackend) Ensure(ctx context.Context) error {
	if err := b.Sets.Ensure(ctx); err != nil {
		return err
	}

	return b.EnsurePolicy(ctx)
}

func (b *ManagedBackend) EnsurePolicy(ctx context.Context) error {
	if b.Prerequisite != nil {
		if err := b.Prerequisite.Ensure(ctx); err != nil {
			return fmt.Errorf("ensure firewall prerequisite: %w", err)
		}
	}

	return b.EnsureRules(ctx)
}

func (b *ManagedBackend) EnsureRules(ctx context.Context) error {
	if err := b.Rules.Ensure(ctx); err != nil {
		return fmt.Errorf("ensure firewall rules: %w", err)
	}

	return nil
}

func (b *ManagedBackend) Block(ctx context.Context, ip net.IP, ttl int) error {
	// A firewall service reload may flush INPUT while the agent remains alive.
	// Reconcile before every new block in addition to the periodic check.
	if err := b.EnsureRules(ctx); err != nil {
		return err
	}

	return b.Sets.Block(ctx, ip, ttl)
}

func (b *ManagedBackend) Unblock(ctx context.Context, ip net.IP) error {
	return b.Sets.Unblock(ctx, ip)
}
