# METADATA
# custom:
#   plainid:
#     policyId: DTCA_CFG_PlainID_PBAC_Author_DEV
#     name: DTCA_CFG_PlainID_PBAC_Author_DEV
#     description: "Users who are members of the DTCA_CFG_PlainID_PBAC_Author_DEV group are allowed to access Composer control points."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: ControlPoints_App
#     customAttributes:
#       regulatoryTags: ["ISO-27001","NIST-SP-800-53"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: DTCA_CFG_PlainID_PBAC_Author_DEV
#     id: 43192b13-23d8-4e90-87a5-9247a7eedfb9
dynamic_group(identity) if {
	identity.template == "User"
	identity["memberofRDN"] == "DTCA_CFG_PlainID_PBAC_Author_DEV"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: Composer Control Points
#     id: 3a441300-27c8-457c-9042-f3f62d964eb3
ruleset(asset, identity, requestParams, action) if {
	asset.template == "ControlPoints"
	startswith(asset["path"], "Composer")
	action.id in ["Access"]
}