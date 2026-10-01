// Example: list configuration counts in an existing Gateway workspace using SCM OAuth.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/gateway"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
)

func main() {
	version := flag.Bool("version", false, "print SDK version and exit")
	workspace := flag.String("workspace-id", "", "existing Gateway workspace ID")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()
	if *version {
		fmt.Println(aisec.Version)
		return
	}
	if *workspace == "" {
		log.Fatal("Set -workspace-id to an existing workspace ID; credentials use PANW_AI_GW_* or PANW_MGMT_*")
	}
	client, err := gateway.NewClient(gateway.Opts{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := client.Configs.List(ctx, schema.ConfigsListOptions{WorkspaceID: *workspace})
	if err != nil {
		log.Fatal(err)
	}
	count := 0
	if response.Data != nil {
		count = len(*response.Data)
	}
	fmt.Printf("SDK %s: Gateway configuration page contains %d entries\n", aisec.Version, count)
}
