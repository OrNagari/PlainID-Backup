# METADATA
# custom:
#   plainid:
#     policyId: ddcc0265-0ba4-4788-8fe7-3f02c6b1678f
#     name: All bankers can access accounts based on their region
#     description: "Bankers with internal user roles can view, edit, or delete active bank accounts in their assigned region."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: Banking-app
#     customAttributes:
#       regulatoryTags: ["PCI-DSS","SOX","ISO-27001","SOC2","NIST-SP-800-53"]
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
#     name: Region match (1)
#     id: 69011f3e-b83b-41c2-9140-aeeb57bddaf0
ruleset(asset, identity, requestParams, action) if {
	asset.template == "Bank_Accounts"
	identity.template == "InternalUsers"
	asset["Region"] == identity["Region"]
	asset["Status"] == "active"
	action.id in ["delete","edit","view"]
}