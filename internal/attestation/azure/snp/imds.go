/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package snp

import (
	"context"
	"fmt"

	"github.com/flashbots/cvm-reverse-proxy/internal/cloud/azure"
)

const tagMAAURL = "constellation-maa-url"

type imdsClient struct {
	imdsClient *azure.IMDSClient
}

func newIMDSClient() *imdsClient {
	return &imdsClient{
		imdsClient: azure.NewIMDSClient(),
	}
}

func (c *imdsClient) getMAAURL(ctx context.Context) (string, error) {
	tags, err := c.imdsClient.Tags(ctx)
	if err != nil {
		return "", fmt.Errorf("getting tags: %w", err)
	}

	return tags[tagMAAURL], nil
}
