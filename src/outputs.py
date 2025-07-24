from soar_sdk.action_results import ActionOutput, OutputField


class ListPlatformsOutput(ActionOutput):
    platforms: list[str]


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


class CreateUpdateGroupOutput(ActionOutput):
    group: IoaGroup


class CreateUpdateRuleOutput(ActionOutput):
    rule: IoaRule


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


class ListSeveritiesOutput(ActionOutput):
    severities: list[str]
