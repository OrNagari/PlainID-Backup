# METADATA
# custom:
#   plainid:
#     policyId: aebe813f-d8e5-4829-9d31-b4e605e44be2
#     name: Test
#     description: "Users with Workspace4 template access can perform actions on test_virtual assets in the Test-App application."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: or
#       - id: test
#       - id: Test-App
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
#     name: All
#     id: 5c17eea5-2dfb-4a7b-9b56-119cd63da303
#     description: "Predefined Ruleset. All Assets contains all created assets defined in the Asset Type"
ruleset(asset, identity, requestParams, action) if {
	asset.template == "test_virtual"
}