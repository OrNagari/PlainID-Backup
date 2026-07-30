# METADATA
# custom:
#   plainid:
#     policyId: a6abc37a-4969-44f0-a842-078053c84f04
#     name: Managers Can View Accounts
#     description: "Users with the Bank Users Demo template can view bank accounts in the bank application."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: bank_application
#     customAttributes:
#       regulatoryTags: ["SOC2","ISO-27001","PCI-DSS","NIST-SP-800-53"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: Role = Managers
#     id: 7a9403ed-f394-45fb-bfb8-c6dcadc7e25f
dynamic_group(identity) if {
	identity.template == "BankUsersDemo"
	identity["role"] == "manager"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: All
#     id: 8d0122e0-d9ea-4e72-896e-d38b341f1ecd
#     description: "Predefined Ruleset. All Assets contains all created assets defined in the Asset Type"
ruleset(asset, identity, requestParams, action) if {
	asset.template == "bank_accounts_demo"
	action.id in ["View"]
}