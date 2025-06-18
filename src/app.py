from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(default="https://api.crowdstrike.com")
    client_id: str
    client_secret: str = AssetField(sensitive=True)


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


if __name__ == "__main__":
    app.cli()
