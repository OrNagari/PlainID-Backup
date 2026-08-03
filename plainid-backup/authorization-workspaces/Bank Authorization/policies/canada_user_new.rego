# METADATA
# custom:
#   plainid:
#     policyId: canada_user_new
#     name: Canada users can view new accounts
#     description: "Users based in Canada with internal user status can view newly created bank accounts owned by specific account holders."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: Banking-app
#       - id: TE-citi
#     customAttributes:
#       regulatoryTags: ["SOX","PCI-DSS","ISO-27001","NIST-SP-800-53"]
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
#     name: new acounts
#     id: ffcf3917-d3db-46ab-9ec0-068ddcfd8033
ruleset(asset, identity, requestParams, action) if {
	asset.template == "Bank_Accounts"
	asset["owner-id"] in ["1", "2", "3", "4"]
	asset["Account_type"] == "new"
	action.id in ["view"]
}