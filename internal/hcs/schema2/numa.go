// Autogenerated code; DO NOT EDIT.

// Schema retrieved from branch 'main' and build '27598.1000.240410-1356'.

/*
 * Schema Open API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 2.4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package hcsschema

type Numa struct {
	VirtualNodeCount       uint8         `json:"VirtualNodeCount,omitempty"`
	PreferredPhysicalNodes []int64       `json:"PreferredPhysicalNodes,omitempty"`
	Settings               []NumaSetting `json:"Settings,omitempty"`
	MaxSizePerNode         uint64        `json:"MaxSizePerNode,omitempty"`
}