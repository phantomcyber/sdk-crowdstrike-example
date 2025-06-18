from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.action_results import ActionOutput
from soar_sdk.logging import getLogger

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
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.info(f"testing connectivity against {asset.base_url}")
    client = asset.get_client()
    logger.info("created crowdstrike client successfully")
    logger.info("querying valid ioa platforms to ensure connectivity")
    platforms: Result = client.query_platforms()
    logger.info(f"found {len(platforms)} platforms")


class ListPlatformsOutput(ActionOutput):
    """
    Output class for listing platforms.
    """

    resources: list[str]


@app.action()
def list_platforms(soar: SOARClient, asset: Asset) -> None:
    """
    List all valid IOA platforms.
    """
    logger.info("listing valid IOA platforms")
    client = asset.get_client()
    platforms: Result = client.query_platforms()
    return ListPlatformsOutput(**platforms)


if __name__ == "__main__":
    app.cli()
