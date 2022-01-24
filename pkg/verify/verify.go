//
// Copyright 2021 Asra Ali.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Implements workflow attestation verification.

package verify

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

func VerifyArtifact(img string) error {
	// Use Cosign to verify a signature on the image.
	ctx := context.Background()
	regopts := options.RegistryOptions{}
	ociremoteOpts, err := regopts.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}
	co := &cosign.CheckOpts{
		RegistryClientOpts: ociremoteOpts,
		// CertEmail:          c.CertEmail,
		// Expect that the issuer is from GitHub
		CertOidcIssuer: "https://token.actions.githubusercontent.com",
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	ref, err = sign.GetAttachedImageRef(ref, "", ociremoteOpts...)
	if err != nil {
		return errors.Wrapf(err, "resolving attachment type %s for image %s", "", img)
	}

	verified, _, err := cosign.VerifyImageSignatures(ctx, ref, co)
	if err != nil {
		return err
	}

	// Verify the build provenance.
	// TODO: Currently I get "invalid payloadType cosign.sigstore.dev/attestation/v1 on envelope. Expected application/vnd.in-toto+json"

	// Extract GitHub context information from signing certificate.
	// TODO: Detect and handle multiple signatures.
	signingCert, err := verified[0].Cert()
	if err != nil {
		return err
	}
	jobWorkflowRef := sigs.CertSubject(signingCert)
	trigger := getExtension(signingCert, "1.3.6.1.4.1.57264.1.2")
	sha := getExtension(signingCert, "1.3.6.1.4.1.57264.1.3")
	name := getExtension(signingCert, "1.3.6.1.4.1.57264.1.4")
	repository := getExtension(signingCert, "1.3.6.1.4.1.57264.1.5")
	workflowRef := getExtension(signingCert, "1.3.6.1.4.1.57264.1.6")

	// Verify that the repo name, workflow path, and trigger name match.
	fmt.Println(jobWorkflowRef)
	fmt.Println(trigger)
	fmt.Println(sha)
	fmt.Println(name)
	fmt.Println(repository)
	fmt.Println(workflowRef)

	// Checkout the workflow path at the commit hash from the cert.

	// Verify the workflow content.
	return nil
}

func getExtension(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), oid) {
			return string(ext.Value)
		}
	}
	return ""
}
