# METADATA
# custom:
#   plainid:
#     policyId: c2e03h_ES
#     name: c2e03h_ES
#     description: "Policy Description for c2e03h"
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: IP-Based-Authorization
#     customAttributes:
#       regulatoryTags: ["ISO-27001","NIST-SP-800-53"]
#       OP-gid: "8b3298c2-0bfe-4b86-81e2-15067235f6ff"
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: c2e03h_ES
#     id: b0df8494-21fc-4942-ae28-3207f09728c7
#     description: "DG Descriptionc2e03h_ES"
dynamic_group(identity) if {
	identity.template == "IP_Based_Authorization"
	identity["MORNETPLUSID"] == "c2e03h"
	identity["USERTYPE"] == "ES"
}

# METADATA
# custom:
#   plainid:
#     kind: Ruleset
#     name: IP Based Authorization_single_assets
#     id: 967453ad-9f88-4b24-a44f-dd95206c2166
#     description: "Single Assets from 4.x for template IP Based Authorization"
ruleset(asset, identity, requestParams, action) if {
	asset.template == "IP Based Authorization"
	asset["path"] == "access"
	action.id in ["Grant"]
}

# METADATA
# custom:
#   plainid:
#     kind: Condition IP
#     name: c2e03h_ES
#     id: 45965913-29cc-4210-98db-abf5287ba683
#     description: "c2e03h_ES"
condition_ip(env) if {
	net.cidr_contains("8.8.8.1/19", env.sourceIp)
}

# METADATA
# custom:
#   plainid:
#     kind: Condition IP
#     name: c2e03h_ES
#     id: 45965913-29cc-4210-98db-abf5287ba683
#     description: "c2e03h_ES"
condition_ip(env) if {
	net.cidr_contains("9.9.9.6/8", env.sourceIp)
}