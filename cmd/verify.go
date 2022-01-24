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

/*
Usage:
	go run ./cmd/verify.go ghcr.io/asraa/slsa-github-demo
*/

package main

import (
	"flag"

	"github.com/asraa/slsa-github-demo/pkg/verify"
)

func main() {
	img := flag.String("image", "", "image to verify")
	flag.Parse()

	if *img == "" {
		flag.Usage()
		return
	}

	// Verify the signature on the provenence, extract the workflow at the commit
	if err := verify.VerifyArtifact(*img); err != nil {
		panic(err)
	}
}
