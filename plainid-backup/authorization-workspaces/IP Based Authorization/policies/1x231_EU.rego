# METADATA
# custom:
#   plainid:
#     policyId: 1x231_EU
#     name: 1x231_EU
#     description: "Policy Description for 1x231"
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: IP-Based-Authorization
#     customAttributes:
#       regulatoryTags: ["ISO-27001","NIST-SP-800-53","GDPR-PII"]
#       OP-gid: "8ca0c638-e9e9-47fb-9b2a-dd19d04fa5db"
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: 1x231_EU
#     id: fcba1238-35fa-420a-b3b6-f255ef778aba
#     description: "DG Description1x231_EU"
dynamic_group(identity) if {
	identity.template == "IP_Based_Authorization"
	identity["MORNETPLUSID"] == "1x231"
	identity["USERTYPE"] == "EU"
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
#     name: 1x324_EU (2)
#     id: 322fa33a-498f-4e96-bdd6-eb64739b1003
#     description: "1x324_EU"
condition_ip(env) if {
	net.cidr_contains("10.0.0.0/4", env.sourceIp)
}