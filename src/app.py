import json
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.params import Params, Param
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger

from typing import Optional

from falconpy import CustomIOA, Result

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(default="https://api.crowdstrike.com")
    client_id: str
    client_secret: str = AssetField(sensitive=True)

    def get_client(self) -> CustomIOA:
        """
        Returns a CustomIOA client instance using the asset's credentials.
        """
        return CustomIOA(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url,
            pythonic=True,
        )


app = App(
    asset_cls=Asset,
    name="crowdstrike_ioa_sdk",
    appid="04bb36b6-0675-43ab-a835-afcd590e62ba",
    app_type="security",
    product_vendor="CrowdStrike",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_name="Falcon",
    publisher="Splunk Inc.",
    min_phantom_version="6.2.2.134",
)


@app.test_connectivity()
def test_connectivity(asset: Asset) -> None:
    logger.info(f"testing connectivity against {asset.base_url}")
    client = asset.get_client()
    logger.info("created crowdstrike client successfully")
    logger.info("querying valid ioa platforms to ensure connectivity")
    platforms: Result = client.query_platforms()
    logger.info(f"found {len(platforms)} platforms")


class ListPlatformsOutput(ActionOutput):
    platforms: list[str]


@app.action()
def list_platforms(params: Params, asset: Asset) -> ListPlatformsOutput:
    """
    List all valid IOA platforms.
    """
    logger.info("listing valid IOA platforms")
    client = asset.get_client()
    platforms: Result = client.query_platforms()
    return ListPlatformsOutput(platforms=platforms.data)


class ListGroupsParameters(Params):
    fql_query: Optional[str] = Param(description="FQL query to filter groups")


class IoaFieldValue(ActionOutput):
    label: str
    value: str


class IoaFieldValues(ActionOutput):
    name: str
    value: str
    label: str
    final_value: str
    values: list[IoaFieldValue]


class IoaRule(ActionOutput):
    instance_id: str = OutputField(cef_types=["crowdstrike ioa rule id"])
    customer_id: str = OutputField(cef_types=["crowdstrike customer id"])
    ruletype_id: str = OutputField(cef_types=["crowdstrike ioa rule type id"])
    ruletype_name: str
    comment: str
    enabled: bool
    deleted: bool
    magic_cookie: int
    rulegroup_id: str = OutputField(cef_types=["crowdstrike ioa rule group id"])
    version_ids: list[str]
    instance_version: int
    name: str
    description: str
    pattern_id: str = OutputField(cef_types=["crowdstrike ioa pattern id"])
    pattern_severity: str
    action_label: str
    disposition_id: int
    created_by: str = OutputField(cef_types=["crowdstrike user id", "email"])
    created_on: str
    modified_by: str = OutputField(cef_types=["crowdstrike user id", "email"])
    modified_on: str
    field_values: list[IoaFieldValues]


class IoaGroup(ActionOutput):
    id: str = OutputField(cef_types=["crowdstrike ioa rule group id"])
    customer_id: str = OutputField(cef_types=["crowdstrike customer id"])
    enabled: bool
    name: str
    description: str
    platform: str
    deleted: bool
    comment: str
    version: int
    created_by: str = OutputField(cef_types=["crowdstrike user id", "email"])
    created_on: str
    modified_by: str = OutputField(cef_types=["crowdstrike user id", "email"])
    modified_on: str
    rule_ids: list[str] = OutputField(cef_types=["crowdstrike ioa rule id"])
    rules: list[IoaRule]


class ListGroupsOutput(ActionOutput):
    rule_groups: list[IoaGroup]


@app.action()
def list_rule_groups(params: ListGroupsParameters, asset: Asset) -> ListGroupsOutput:
    """
    List IOA rule groups.
    """
    logger.info("listing IOA rule groups")
    client = asset.get_client()

    rule_groups = []
    offset = 0
    limit = 100
    while True:
        result = client.query_rule_groups_full(
            filter=params.fql_query, offset=offset, limit=limit
        )
        rule_groups.extend(result.data)
        if result.offset >= result.total:
            break
        offset = result.offset

    return ListGroupsOutput(rule_groups=rule_groups)


class CreateGroupParams(Params):
    name: str
    description: Optional[str]
    platform: str
    enabled: bool
    policy_id: Optional[str] = Param(
        description="Prevention Policy ID to assign the new group to",
        cef_types=["crowdstrike prevention policy id"],
    )


class CreateUpdateGroupOutput(ActionOutput):
    group: IoaGroup


@app.action()
def create_rule_group(
    params: CreateGroupParams, asset: Asset
) -> CreateUpdateGroupOutput:
    """
    Create a new IOA rule group.
    """
    logger.info(f"creating IOA rule group with name {params.name}")
    client = asset.get_client()

    response = client.create_rule_group(
        name=params.name,
        description=params.description,
        platform=params.platform,
        enabled=params.enabled,
        policy_id=params.policy_id,
    )

    group = response.data[0]
    if params.enabled:
        logger.info(f"enabling IOA rule group {group['id']}")
        group["enabled"] = True
        response = client.update_rule_group(
            id=group["id"],
            name=group["name"],
            description=group["description"],
            rulegroup_version=group["version"],
            enabled=True,
            comment="Enabling newly-created group",
        )
        group = response.data[0]

    return CreateUpdateGroupOutput(group=group)


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


@app.action()
def update_rule_group(
    params: UpdateGroupParams, asset: Asset
) -> CreateUpdateGroupOutput:
    """
    Update an existing IOA rule group.
    """
    logger.info(f"updating IOA rule group with ID {params.id}")
    client = asset.get_client()

    response = client.update_rule_group(
        id=params.id,
        name=params.name,
        description=params.description,
        rulegroup_version=params.version,
        enabled=params.enabled,
        comment=params.comment,
    )

    group = response.data[0]
    return CreateUpdateGroupOutput(group=group)


class DeleteGroupParams(Params):
    id: str = Param(
        description="ID of the IOA rule group to delete",
        cef_types=["crowdstrike ioa rule group id"],
    )
    comment: str = Param(description="Comment for deletion")


@app.action()
def delete_rule_group(params: DeleteGroupParams, asset: Asset) -> ActionOutput:
    """
    Delete an existing IOA rule group.
    """
    logger.info(f"deleting IOA rule group with ID {params.id}")
    client = asset.get_client()

    client.delete_rule_groups(
        ids=[params.id],
        comment=params.comment,
    )

    return ActionOutput()


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


class CreateUpdateRuleOutput(ActionOutput):
    rule: IoaRule


@app.action()
def create_rule(params: CreateRuleParams, asset: Asset) -> CreateUpdateRuleOutput:
    """
    Create a new IOA rule in the specified group.
    """
    logger.info(f"creating IOA rule in group {params.rulegroup_id}")
    client = asset.get_client()

    field_values = json.loads(params.field_values)

    response = client.create_rule(
        rulegroup_id=params.rulegroup_id,
        name=params.name,
        description=params.description,
        pattern_severity=params.severity,
        ruletype_id=params.ruletype_id,
        disposition_id=params.disposition_id,
        field_values=field_values,
        comment=params.comment,
    )
    rule = response.data[0]

    if params.enabled:
        logger.info(f"enabling newly-created IOA rule {rule['instance_id']}")
        response = client.update_rules_v2(
            rulegroup_id=params.rulegroup_id,
            rulegroup_version=rule["magic_cookie"],
            rule_updates={"instance_id": rule["instance_id"], "enabled": True},
            comment="Enabling newly-created rule",
        )
        rule_group = response.data[0]
        for r in rule_group["rules"]:
            if r["instance_id"] == rule["instance_id"]:
                rule = r
                break

    return CreateUpdateRuleOutput(rule=rule)


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
    name: Optional[str]
    description: Optional[str]
    severity: Optional[str]
    disposition_id: Optional[int]
    field_values: Optional[str]


@app.action()
def update_rule(params: UpdateRuleParams, asset: Asset) -> CreateUpdateRuleOutput:
    """
    Update an existing IOA rule.
    """
    logger.info(
        f"updating IOA rule {params.instance_id} in group {params.rulegroup_id}"
    )
    client = asset.get_client()

    rule_updates = {
        "instance_id": params.instance_id,
    }
    if params.name is not None:
        rule_updates["name"] = params.name
    if params.description is not None:
        rule_updates["description"] = params.description
    if params.severity is not None:
        rule_updates["pattern_severity"] = params.severity
    if params.disposition_id is not None:
        rule_updates["disposition_id"] = params.disposition_id
    if params.field_values is not None:
        rule_updates["field_values"] = json.loads(params.field_values)

    response = client.update_rules_v2(
        rulegroup_id=params.rulegroup_id,
        rulegroup_version=params.rulegroup_version,
        comment=params.comment,
        rule_updates=rule_updates,
    )
    rule_group = response.data[0]
    for rule in rule_group["rules"]:
        if rule["instance_id"] == params.instance_id:
            return CreateUpdateRuleOutput(rule=rule)


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


@app.action()
def delete_rule(params: DeleteRuleParams, asset: Asset) -> ActionOutput:
    """
    Delete an existing IOA rule.
    """
    logger.info(
        f"deleting IOA rule {params.instance_id} in group {params.rulegroup_id}"
    )
    client = asset.get_client()

    client.delete_rules(
        rule_group_id=params.rulegroup_id,
        ids=[params.instance_id],
        comment=params.comment,
    )

    return ActionOutput()


class ListSeveritiesOutput(ActionOutput):
    severities: list[str]


@app.action()
def list_severities(params: Params, asset: Asset) -> ListSeveritiesOutput:
    """
    List all valid IOA severities.
    """
    logger.info("listing valid IOA severities")
    client = asset.get_client()
    severities = client.query_patterns()
    return ListSeveritiesOutput(severities=severities.data)


class IoaRuleDisposition(ActionOutput):
    id: int
    label: str


class IoaFieldOption(ActionOutput):
    label: str
    value: str


class IoaField(ActionOutput):
    name: str
    label: str
    type: str
    options: list[IoaFieldOption]


class IoaRuleType(ActionOutput):
    id: str
    name: str
    channel: int
    long_desc: str
    released: bool
    platform: str
    fields: list[IoaField]
    disposition_map: list[IoaRuleDisposition]


class ListRuleTypesOutput(ActionOutput):
    rule_types: list[IoaRuleType]


@app.action()
def list_rule_types(params: Params, asset: Asset) -> ListRuleTypesOutput:
    """
    List all valid IOA rule types.
    """
    logger.info("listing valid IOA rule types")
    client = asset.get_client()

    rule_types = []
    offset = 0
    limit = 100
    while True:
        ids_result = client.query_rule_types(offset=offset, limit=limit)
        ids = ",".join(ids_result.data)
        rules_result = client.get_rule_types(ids=ids)
        rule_types.extend(rules_result.data)
        if ids_result.offset >= ids_result.total:
            break
        offset = ids_result.offset

    return ListRuleTypesOutput(rule_types=rule_types)


if __name__ == "__main__":
    app.cli()
