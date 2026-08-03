# METADATA
# custom:
#   plainid:
#     policyId: 1x324_EU
#     name: 1x324_EU
#     description: "Policy Description for 1x324"
#     accessType: Allow
#     policyUse: DYNAMIC_AUTHORIZATION_SERVICE
#     sourceEnvironmentId: d472c63d-9ab4-44a5-8f57-250f6e016384
#     applications: 
#       - id: IP-Based-Authorization
#     customAttributes:
#       regulatoryTags: ["GDPR-PII","ISO-27001","ISO-27701"]
#       OP-gid: "3414a39a-c619-43a6-bee2-399bf9165aca"
package policy
import rego.v1

# METADATA
# custom:
#   plainid:
#     kind: DynamicGroup
#     name: 1x324_EU
#     id: b11e3daa-063a-4b35-afb1-db1c06bd1ad4
#     description: "DG Description1x324_EU"
dynamic_group(identity) if {
	identity.template == "IP_Based_Authorization"
	identity["MORNETPLUSID"] == "1x324"
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
#     name: 1x324_EU (1)
#     id: 1926797b-c1ab-472b-be24-54120c14a25d
#     description: "1x324_EU"
condition_ip(env) if {
	net.cidr_contains("10.0.0.0/8", env.sourceIp)
}