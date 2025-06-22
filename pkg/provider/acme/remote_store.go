package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
)

type RemoteConfig struct {
	Account      *Account
	Certificates []*CertAndStore
}

// LocalStore Stores implementation for local file.
type RemoteStore struct {
	endpoint string
	lock     sync.RWMutex
	cfg      *RemoteConfig
}

// NewLocalStore initializes a new LocalStore with a file name.
func NewRemoteStore(endpoint string, routinesPool *safe.Pool) *RemoteStore {
	return &RemoteStore{endpoint: endpoint}
}

func (s *RemoteStore) refresh() error {
	fmt.Printf("remote_store: starting refresh\n")
	c := http.Client{Timeout: time.Duration(10) * time.Second}
	resp, err := c.Get(s.endpoint)
	if err != nil {
		fmt.Printf("remote_store: error in refresh: %s\n", err)
		return err
	}
	fmt.Printf("remote_store: got response\n")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("remote_store: error parsing response - %s\n", err)
		return err
	}
	cfg := &RemoteConfig{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return err
	}
	fmt.Printf("remote_store: locking\n")
	s.lock.Lock()
	defer s.lock.Unlock()
	fmt.Printf("remote_store: locked\n")
	s.cfg = cfg
	return nil
}

// GetAccount returns ACME Account.
func (s *RemoteStore) GetAccount(resolverName string) (*Account, error) {
	if err := s.refresh(); err != nil {
		return nil, err
	}
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cfg.Account, nil
}

// SaveAccount stores ACME Account.
func (s *RemoteStore) SaveAccount(resolverName string, account *Account) error {
	return fmt.Errorf("not implemented")
}

// GetCertificates returns ACME Certificates list.
func (s *RemoteStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	if err := s.refresh(); err != nil {
		return nil, err
	}
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cfg.Certificates, nil
}

// SaveCertificates stores ACME Certificates list.
func (s *RemoteStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	return fmt.Errorf("not implemented")
}

// Provider holds configurations of the provider.
type RemoteProvider struct {
	*Configuration
	ResolverName string
	Store        Store `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`

	certificates   []*CertAndStore
	certificatesMu sync.RWMutex

	configurationChan      chan<- dynamic.Message
	configFromListenerChan chan dynamic.Configuration
	pool                   *safe.Pool
}

// SetConfigListenerChan initializes the configFromListenerChan.
func (p *RemoteProvider) SetConfigListenerChan(configFromListenerChan chan dynamic.Configuration) {
	p.configFromListenerChan = configFromListenerChan
}

// ListenConfiguration sets a new Configuration into the configFromListenerChan.
func (p *RemoteProvider) ListenConfiguration(config dynamic.Configuration) {
	fmt.Println("listen incoming")
	p.configFromListenerChan <- config
	fmt.Println("listen handled")
}

// Init inits the provider.
func (p *RemoteProvider) Init() error {
	if len(p.Configuration.Storage) == 0 {
		return errors.New("unable to initialize ACME provider with no storage location for the certificates")
	}
	if p.CertificatesDuration < 1 {
		return errors.New("cannot manage certificates with duration lower than 1 hour")
	}
	if p.ClientTimeout < p.ClientResponseHeaderTimeout {
		return errors.New("clientTimeout must be at least clientResponseHeaderTimeout")
	}
	if _, err := p.Store.GetAccount(p.ResolverName); err != nil {
		return fmt.Errorf("unable to get ACME account: %w", err)
	}
	return nil
}

func (p *RemoteProvider) updateFromStore(ctx context.Context) {
	logger := log.Ctx(ctx)
	certs, err := p.Store.GetCertificates("")
	if err != nil {
		logger.Error().Err(err).Msgf("error fetching certificates")
	}
	logger.Info().Msgf("Got %d certificate(s) from %s", len(certs), p.RemoteEndpoint)
	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()
	p.certificates = certs
}

func (p *RemoteProvider) refreshCertificates(ctx context.Context) {
	logger := log.Ctx(ctx)
	logger.Info().Msgf("fetching certificates from %s", p.RemoteEndpoint)
	p.updateFromStore(ctx)
	msg := p.buildMessage()
	p.configurationChan <- msg
	logger.Info().Msgf("Sent configuration update")
}

// Provide allows the file provider to provide configurations to traefik
// using the given Configuration channel.
func (p *RemoteProvider) Provide(configurationChan chan<- dynamic.Message, pool *safe.Pool) error {
	logger := log.With().Str(logs.ProviderName, p.ResolverName+resolverSuffix).Str("acmeCA", p.Configuration.CAServer).
		Logger()
	ctx := logger.WithContext(context.Background())
	p.pool = pool
	p.configurationChan = configurationChan
	p.watch(ctx)
	ticker := time.NewTicker(time.Minute)
	pool.GoCtx(func(ctxPool context.Context) {
		logger.Info().Msgf("Start Background Remote Store Worker")
		for {
			select {
			case <-ticker.C:
				logger.Info().Msgf("Starting background certificate refresh")
				p.refreshCertificates(ctx)
			case <-ctxPool.Done():
				logger.Info().Msgf("Pool context is done. Stopping ticker")
				ticker.Stop()
				return
			}
		}
	})
	p.refreshCertificates(ctx)
	return nil
}

func (p *RemoteProvider) watch(ctx context.Context) {
	p.pool.GoCtx(func(ctxPool context.Context) {
		for {
			select {
			case config := <-p.configFromListenerChan:
				fmt.Printf("got config: %+v\n", config)
			case <-ctxPool.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	})
}

func (p *RemoteProvider) buildMessage() dynamic.Message {
	p.certificatesMu.RLock()
	defer p.certificatesMu.RUnlock()
	conf := dynamic.Message{
		ProviderName: p.ResolverName + ".acme",
		Configuration: &dynamic.Configuration{
			HTTP: &dynamic.HTTPConfiguration{
				Routers:     map[string]*dynamic.Router{},
				Middlewares: map[string]*dynamic.Middleware{},
				Services:    map[string]*dynamic.Service{},
			},
			TLS: &dynamic.TLSConfiguration{},
		},
	}
	for _, cert := range p.certificates {
		certConf := &traefiktls.CertAndStores{
			Certificate: traefiktls.Certificate{
				CertFile: types.FileOrContent(cert.Certificate.Certificate),
				KeyFile:  types.FileOrContent(cert.Key),
			},
			Stores: []string{cert.Store},
		}
		conf.Configuration.TLS.Certificates = append(conf.Configuration.TLS.Certificates, certConf)
	}

	return conf
}
