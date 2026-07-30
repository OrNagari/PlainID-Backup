# METADATA
# custom:
#   plainid:
#     policyId: Canada_users_can_view_public_accounts
#     name: Canada users can view public accounts
#     description: "Users from Canada can view public bank accounts."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: Banking-app
#     customAttributes:
#       regulatoryTags: ["PCI-DSS","ISO-27001","NIST-SP-800-53"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: Canada users
#     id: eecf8765-d7fd-4537-b901-8550052ebd89
dynamic_group(identity) if {
	identity.template == "InternalUsers"
	identity["Region"] == "Canada"
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