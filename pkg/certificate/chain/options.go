package chain

import (
	"fmt"
	"time"
)

const (
	OneYearDuration = 365 * 24 * time.Hour
)

func (o *Options) validate() error {
	if o.CAOverlapInterval > o.CARotateInterval {
		return fmt.Errorf("failed validating certificate options, 'CAOverlapInterval' has to be <= 'CARotateInterval'")
	}

	if o.CertRotateInterval > o.CARotateInterval {
		return fmt.Errorf("failed validating certificate options, 'CertRotateInterval' has to be <= 'CARotateInterval'")
	}

	if o.CertOverlapInterval > o.CertRotateInterval {
		return fmt.Errorf("failed validating certificate options, 'CertOverlapInterval' has to be <= 'CertRotateInterval'")
	}

	return nil

}

func (o Options) withDefaults() Options {
	withDefaultsOptions := o

	if o.CARotateInterval == 0 {
		withDefaultsOptions.CARotateInterval = OneYearDuration
	}

	if o.CAOverlapInterval == 0 {
		withDefaultsOptions.CAOverlapInterval = withDefaultsOptions.CARotateInterval
	}

	if o.CertRotateInterval == 0 {
		withDefaultsOptions.CertRotateInterval = withDefaultsOptions.CARotateInterval
	}

	if o.CertOverlapInterval == 0 {
		withDefaultsOptions.CertOverlapInterval = withDefaultsOptions.CertRotateInterval
	}
	return withDefaultsOptions
}

func (o *Options) SetDefaultsAndValidate() error {
	withDefaultsOptions := o.withDefaults()
	err := withDefaultsOptions.validate()
	if err != nil {
		return err
	}
	*o = withDefaultsOptions
	return nil
}
