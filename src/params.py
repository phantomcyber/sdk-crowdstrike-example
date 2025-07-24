from soar_sdk.params import Param, Params


class ListGroupsParameters(Params):
    fql_query: str = Param(description="FQL query to filter groups", required=False)


class CreateGroupParams(Params):
    name: str
    description: str = Param(required=False)
    platform: str
    enabled: bool
    policy_id: str = Param(
        description="Prevention Policy ID to assign the new group to",
        cef_types=["crowdstrike prevention policy id"],
        required=False,
    )


class UpdateGroupParams(Params):
    id: str = Param(
        description="ID of the IOA rule group to update",
        cef_types=["crowdstrike ioa rule group id"],
    )
    version: int = Param(description="Latest version of the group")
    name: str
    description: str
    enabled: bool
    comment: str


class DeleteGroupParams(Params):
    id: str = Param(
        description="ID of the IOA rule group to delete",
        cef_types=["crowdstrike ioa rule group id"],
    )
    comment: str = Param(description="Comment for deletion")


class CreateRuleParams(Params):
    rulegroup_id: str = Param(
        description="ID of the IOA rule group to add the rule to",
        cef_types=["crowdstrike ioa rule group id"],
    )
    name: str
    description: str
    severity: str
    ruletype_id: str = Param(
        description="Rule type to create (valid rule types can be fetched using the 'list rule types' action)",
    )
    disposition_id: int = Param(
        description="The action that the rule should take (valid dispositions can be fetched using the 'list rule types' action)",
    )
    field_values: str = Param(
        description="JSON list of parameter values for the rule (valid values can be fetched using the 'list rule types' action)",
    )
    comment: str
    enabled: bool


class UpdateRuleParams(Params):
    rulegroup_id: str = Param(
        description="ID of the IOA rule group that contains the rule",
        cef_types=["crowdstrike ioa rule group id"],
    )
    rulegroup_version: int
    instance_id: str = Param(
        description="ID of the IOA rule to update",
        cef_types=["crowdstrike ioa rule id"],
    )
    comment: str
    name: str = Param(required=False)
    description: str = Param(required=False)
    severity: str = Param(required=False)
    disposition_id: int = Param(required=False)
    field_values: str = Param(required=False)


class DeleteRuleParams(Params):
    rulegroup_id: str = Param(
        description="ID of the IOA rule group that contains the rule",
        cef_types=["crowdstrike ioa rule group id"],
    )
    instance_id: str = Param(
        description="ID of the IOA rule to delete",
        cef_types=["crowdstrike ioa rule id"],
    )
    comment: str
