import json
from falconpy import CustomIOA, Result

from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.params import Params
from soar_sdk.action_results import ActionOutput
from soar_sdk.logging import getLogger

from src.params import (
    CreateGroupParams,
    CreateRuleParams,
    DeleteGroupParams,
    DeleteRuleParams,
    ListGroupsParameters,
    UpdateGroupParams,
    UpdateRuleParams,
)
from src.outputs import (
    CreateUpdateGroupOutput,
    CreateUpdateRuleOutput,
    ListGroupsOutput,
    ListPlatformsOutput,
    ListRuleTypesOutput,
    ListSeveritiesOutput,
)

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


@app.action()
def list_platforms(params: Params, asset: Asset) -> ListPlatformsOutput:
    """
    List all valid IOA platforms.
    """
    logger.info("listing valid IOA platforms")
    client = asset.get_client()
    platforms: Result = client.query_platforms()
    return ListPlatformsOutput(platforms=platforms.data)


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


@app.action()
def list_severities(params: Params, asset: Asset) -> ListSeveritiesOutput:
    """
    List all valid IOA severities.
    """
    logger.info("listing valid IOA severities")
    client = asset.get_client()
    severities = client.query_patterns()
    return ListSeveritiesOutput(severities=severities.data)


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
