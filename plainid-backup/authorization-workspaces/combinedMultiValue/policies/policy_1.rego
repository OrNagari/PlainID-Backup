# METADATA
# custom:
#   plainid:
#     policyId: policy_1
#     name: policy_1
#     description: "External users can create resources at locations where their department and location attributes match the resource's department and location attributes."
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: CMV-app
#     customAttributes:
#       regulatoryTags: ["ISO-27001"]
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: External Users All Users
#     id: 5fe28ad9-bcf9-4865-8e47-8ea98fcb037c
#     description: "Predefined Dynamic Group. All Users contains all organization's users defined in the IDP"
dynamic_group(identity) if {
	identity.template == "ExternalUsers"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: DEPT and LOCATION
#     id: 92e183e5-8d24-4bb4-b412-827121edf164
ruleset(asset, identity, requestParams, action) if {
	asset.template == "LOCATION"
	identity.template == "ExternalUsers"
	asset["DEPT"] == identity["DEPT"]
	asset["LOCATION"] == identity["LOCATION"]
	action.id in ["create"]
}