package uvm

import (
	"fmt"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

// prepareVNumaTopology creates vNUMA settings for implicit (platform) or explicit (user-defined) topology.
//
// For implicit topology we look for `MaxProcessorsPerNumaNode` and `MaxSizePerNode` create options. Setting them
// in HCS doc, will trigger platform to create vNUMA topology based on the given values. Based on experiments, the
// platform will create an evenly distributed topology based on requested memory and processor count for the HCS VM.
//
// For explicit topology we look for `NumaMappedPhysicalNodes`, `NumaProcessorCounts` and `NumaMemoryBlocksCounts` create
// options. The above options are number slices, where a value at index `i` in each slice represents the corresponding
// value for the `i`th vNUMA node.
// Limitations:
// - only hcsschema.MemoryBackingType_PHYSICAL is supported
// - `PhysicalNumaNodes` values at index `i` will be mapped to virtual node number `i`
// - client is responsible for setting wildcard physical node numbers
//
// TODO: We also assume that `hcsschema.Numa.PreferredPhysicalNodes` can be used for implicit placement as well as
// for explicit placement in the case when all wildcard physical nodes are present.
func prepareVNumaTopology(opts *Options) (*hcsschema.Numa, *hcsschema.NumaProcessors, error) {
	if opts.MaxProcessorsPerNumaNode == 0 && len(opts.NumaMappedPhysicalNodes) == 0 {
		// vNUMA settings are missing, return empty topology
		return nil, nil, nil
	}

	var preferredNumaNodes []int64
	for _, pn := range opts.PreferredPhysicalNumaNodes {
		preferredNumaNodes = append(preferredNumaNodes, int64(pn))
	}

	// Implicit vNUMA topology.
	if opts.MaxProcessorsPerNumaNode > 0 {
		if opts.MaxSizePerNode == 0 {
			return nil, nil, fmt.Errorf("max size per node must be set when max processors per numa node is set")
		}
		numaProcessors := &hcsschema.NumaProcessors{
			CountPerNode: hcsschema.Range{
				Max: opts.MaxProcessorsPerNumaNode,
			},
		}
		numa := &hcsschema.Numa{
			MaxSizePerNode:         opts.MaxSizePerNode,
			PreferredPhysicalNodes: preferredNumaNodes,
		}
		return numa, numaProcessors, nil
	}

	// Explicit vNUMA topology.

	numaNodeCount := len(opts.NumaMappedPhysicalNodes)
	if numaNodeCount != len(opts.NumaProcessorCounts) || numaNodeCount != len(opts.NumaMemoryBlocksCounts) {
		return nil, nil, fmt.Errorf("mismatch in number of physical numa nodes and the corresponding processor and memory blocks count")
	}

	numa := &hcsschema.Numa{
		VirtualNodeCount:       uint8(numaNodeCount),
		Settings:               []hcsschema.NumaSetting{},
		PreferredPhysicalNodes: preferredNumaNodes,
	}
	for i := 0; i < numaNodeCount; i++ {
		nodeTopology := hcsschema.NumaSetting{
			VirtualNodeNumber:   uint32(i),
			PhysicalNodeNumber:  opts.NumaMappedPhysicalNodes[i],
			VirtualSocketNumber: uint32(i),
			MemoryBackingType:   hcsschema.MemoryBackingType_PHYSICAL,
			CountOfProcessors:   opts.NumaProcessorCounts[i],
			CountOfMemoryBlocks: opts.NumaMemoryBlocksCounts[i],
		}
		numa.Settings = append(numa.Settings, nodeTopology)
	}
	return numa, nil, numa.Validate()
}
