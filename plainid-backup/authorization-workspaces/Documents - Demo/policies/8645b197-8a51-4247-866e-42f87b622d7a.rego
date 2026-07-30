# METADATA
# custom:
#   plainid:
#     policyId: 8645b197-8a51-4247-866e-42f87b622d7a
#     name: Users can edit documents
#     description: "Users matching the Bank Users Demo template are allowed to edit documents in the documents application."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: documents
#     customAttributes:
#       regulatoryTags: ["ISO-27001","SOC2"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: Bank Users - Demo All Users
#     id: 18d6b0a7-d3d4-4857-bb8d-683c583ebece
#     description: "Predefined Dynamic Group. All Users contains all organization's users defined in the IDP"
dynamic_group(identity) if {
	identity.template == "BankUsersDemo"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: All
#     id: d411bb15-4a9d-43bb-8a8d-c1a6cb01e973
#     description: "Predefined Ruleset. All Assets contains all created assets defined in the Asset Type"
ruleset(asset, identity, requestParams, action) if {
	asset.template == "documents"
	action.id in ["Edit"]
}