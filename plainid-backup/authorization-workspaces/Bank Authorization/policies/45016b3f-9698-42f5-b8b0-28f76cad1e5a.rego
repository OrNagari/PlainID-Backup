# METADATA
# custom:
#   plainid:
#     policyId: 45016b3f-9698-42f5-b8b0-28f76cad1e5a
#     name: test TE citi
#     description: "Internal users can access test-TE-citi assets where they are listed as the owner and their role matches the asset's LDAP group, but only for the Access action."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: TE-citi
#     customAttributes:
#       regulatoryTags: ["ISO-27001","ISO-27701","SOC2","NIST-SP-800-53","SOX"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: admin group
#     id: a14a12d7-97bb-473b-aba1-9befcbe299d2
dynamic_group(identity) if {
	identity.template == "InternalUsers"
	identity["role"] in ["adminTest", "or"]
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: LDAP
#     id: 63b92583-24c3-4425-ace0-a810874a0385
ruleset(asset, identity, requestParams, action) if {
	asset.template == "TE-Res"
	identity.template == "InternalUsers"
	asset["path"] == "A"
	asset["User"] == identity["uid"]
	asset["LDAP-Group"] == identity["role"]
	action.id in ["Access"]
}