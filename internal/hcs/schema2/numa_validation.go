package hcsschema

import "fmt"

// Validate validates self-contained fields within the given NUMA settings.
//
// TODO (maksiman): Check if we need to add compute-less node validation. For now, assume that it's supported.
func (n *Numa) Validate() error {
	if len(n.Settings) == 0 {
		// Nothing to validate
		return nil
	}

	var virtualNodeSet = make(map[uint32]struct{})
	var virtualSocketSet = make(map[uint32]struct{})
	var totalVPCount uint32
	var totalMemInMb uint64
	var highestVNodeNumber uint32
	var highestVSocketNumber uint32

	hasWildcardPhysicalNode := n.Settings[0].PhysicalNodeNumber == WildcardPhysicalNodeNumber

	for _, topology := range n.Settings {
		if topology.VirtualNodeNumber > NumaChildNodeCountMax {
			return fmt.Errorf("vNUMA virtual node number %d exceeds maximum allowed value %d", topology.VirtualNodeNumber, NumaChildNodeCountMax)
		}
		if topology.PhysicalNodeNumber != WildcardPhysicalNodeNumber && topology.PhysicalNodeNumber >= NumaTopologyNodeCountMax {
			return fmt.Errorf("vNUMA physical node number %d exceeds maximum allowed value %d", topology.PhysicalNodeNumber, NumaTopologyNodeCountMax)
		}
		if hasWildcardPhysicalNode != (topology.PhysicalNodeNumber == WildcardPhysicalNodeNumber) {
			return fmt.Errorf("vNUMA has a mix of wildcard (%d) and non-wildcard (%d) physical node numbers", WildcardPhysicalNodeNumber, topology.PhysicalNodeNumber)
		}

		if topology.CountOfMemoryBlocks == 0 {
			return fmt.Errorf("vNUMA nodes with no memory are not allowed")
		}

		totalVPCount += topology.CountOfProcessors
		totalMemInMb += topology.CountOfMemoryBlocks

		if _, ok := virtualNodeSet[topology.VirtualNodeNumber]; ok {
			return fmt.Errorf("vNUMA virtual node number %d is duplicated", topology.VirtualNodeNumber)
		}
		virtualNodeSet[topology.VirtualNodeNumber] = struct{}{}

		if topology.MemoryBackingType != MemoryBackingType_PHYSICAL && topology.MemoryBackingType != MemoryBackingType_VIRTUAL {
			return fmt.Errorf("vNUMA memory backing type %s is invalid", topology.MemoryBackingType)
		}

		if highestVNodeNumber < topology.VirtualNodeNumber {
			highestVNodeNumber = topology.VirtualNodeNumber
		}
		if highestVSocketNumber < topology.VirtualSocketNumber {
			highestVSocketNumber = topology.VirtualSocketNumber
		}

		virtualSocketSet[topology.VirtualSocketNumber] = struct{}{}
	}

	// Either both total memory and processor count should be zero or both should be non-zero
	if (totalMemInMb == 0) != (totalVPCount == 0) {
		return fmt.Errorf("partial resource allocation is not allowed")
	}

	// At least
	if totalMemInMb == 0 && hasWildcardPhysicalNode {
		return fmt.Errorf("completely empty topology is not allowed")
	}

	if len(virtualNodeSet) != int(highestVNodeNumber+1) {
		return fmt.Errorf("holes in vNUMA node numbers are not allowed")
	}

	if len(virtualSocketSet) != int(highestVSocketNumber+1) {
		return fmt.Errorf("holes in vNUMA socket numbers are not allowed")
	}
	return nil
}

// ValidateNumaForVM validates the NUMA settings for a VM with the given memory settings `memorySettings`,
// processor count `procCount`, and total memory in MB `memInMb`.
func ValidateNumaForVM(numa *Numa, vmMemoryBackingType MemoryBackingType, procCount int32, memInMb uint64) error {
	var hasVirtuallyBackedNode, hasPhysicallyBackedNode bool
	var totalMemoryInMb uint64
	var totalProcessorCount uint32

	for _, topology := range numa.Settings {
		if topology.MemoryBackingType != vmMemoryBackingType && topology.MemoryBackingType != MemoryBackingType_HYBRID {
			return fmt.Errorf("vNUMA memory backing type %s does not match UVM memory backing type %s", topology.MemoryBackingType, vmMemoryBackingType)
		}
		if topology.MemoryBackingType == MemoryBackingType_PHYSICAL {
			hasPhysicallyBackedNode = true
		}
		if topology.MemoryBackingType == MemoryBackingType_VIRTUAL {
			hasVirtuallyBackedNode = true
		}
		totalProcessorCount += topology.CountOfProcessors
		totalMemoryInMb += topology.CountOfMemoryBlocks
	}

	if vmMemoryBackingType == MemoryBackingType_HYBRID {
		if !hasVirtuallyBackedNode || !hasPhysicallyBackedNode {
			return fmt.Errorf("vNUMA must have both physically and virtually backed nodes for UVM with hybrid memory")
		}
	}

	if (totalProcessorCount != 0) && (int32(totalProcessorCount) != procCount) {
		return fmt.Errorf("vNUMA total processor count %d does not match UVM processor count %d", totalProcessorCount, procCount)
	}

	if (totalMemoryInMb != 0) && (totalMemoryInMb != memInMb) {
		return fmt.Errorf("vNUMA total memory %d does not match UVM memory %d", totalMemoryInMb, memInMb)
	}
	return nil
}
