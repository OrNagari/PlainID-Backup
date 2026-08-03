# METADATA
# custom:
#   plainid:
#     policyId: da2a9bee-0735-4ec2-8bdc-68885a56e61c
#     name: USA users can view public accounts
#     description: "Users from USA can view public bank accounts."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: Banking-app
#       - id: TE-citi
#     customAttributes:
#       regulatoryTags: ["PCI-DSS","ISO-27001","NIST-SP-800-53"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: USA users
#     id: 93209007-fb93-44da-a7b3-faee36ea21f1
dynamic_group(identity) if {
	identity.template == "InternalUsers"
	identity["Region"] == "USA"
	identity["department"] == "T"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: public acounts (1)
#     id: 5e84c161-aaeb-43e3-955e-45d8a070ea13
ruleset(asset, identity, requestParams, action) if {
	asset.template == "Bank_Accounts"
	asset["Account_type"] == "public"
	action.id in ["view"]
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: public acounts (1)
#     id: 5e84c161-aaeb-43e3-955e-45d8a070ea13
ruleset(asset, identity, requestParams, action) if {
	asset.template == "Bank_Accounts"
	identity.template == "InternalUsers"
	asset["Region"] == identity["Region"]
	action.id in ["view"]
}