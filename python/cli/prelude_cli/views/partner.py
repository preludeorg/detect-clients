import click

from prelude_cli.views.shared import Spinner, pretty_print
from prelude_sdk.controllers.partner_controller import PartnerController
from prelude_sdk.models.codes import Control


@click.group()
@click.pass_context
def partner(ctx):
    """Partner system commands"""
    ctx.obj = PartnerController(account=ctx.obj)


@partner.command("attach")
@click.argument(
    "partner",
    type=click.Choice(
        [c.name for c in Control if c != Control.INVALID], case_sensitive=False
    ),
)
@click.option("--instance_id", help="instance ID of the partner")
@click.option("--name", help="Friendly name of the partner instance")
@click.option("--api", help="API endpoint of the partner")
@click.option("--user", help="user identifier")
@click.option("--secret", help="secret for OAUTH use cases")
@click.pass_obj
@pretty_print
def attach_partner(controller, partner, instance_id, name, api, user, secret):
    """Attach an EDR to Detect"""
    with Spinner(description="Attaching partner"):
        return controller.attach(
            partner=Control[partner],
            api=api,
            user=user,
            secret=secret,
            name=name,
            instance_id=instance_id,
        )


@partner.command("detach")
@click.confirmation_option(prompt="Are you sure?")
@click.argument(
    "partner",
    type=click.Choice(
        [c.name for c in Control if c != Control.INVALID], case_sensitive=False
    ),
)
@click.option("--instance_id", required=True, help="instance ID of the partner")
@click.pass_obj
@pretty_print
def detach_partner(controller, partner, instance_id):
    """Detach an existing partner from your account"""
    with Spinner(description="Detaching partner"):
        return controller.detach(partner=Control[partner], instance_id=instance_id)


@partner.command("block")
@click.argument(
    "partner",
    type=click.Choice(
        [c.name for c in Control if c != Control.INVALID], case_sensitive=False
    ),
)
@click.option("-t", "--test_id", required=True, help="a test to block")
@click.pass_obj
@pretty_print
def partner_block(controller, partner, test_id):
    """Report to a partner to block a test"""
    with Spinner(description="Reporting test to partner"):
        return controller.block(partner=Control[partner], test_id=test_id)


@partner.command("endpoints")
@click.argument(
    "partner",
    type=click.Choice(
        [c.name for c in Control if c != Control.INVALID], case_sensitive=False
    ),
)
@click.option(
    "--platform",
    help='platform name (e.g. "windows")',
    required=True,
    type=click.Choice(["windows", "linux", "darwin"], case_sensitive=False),
)
@click.option(
    "--hostname", default="", help='hostname pattern (e.g. "mycompany-c24oi444")'
)
@click.option("--offset", default=0, help="API pagination offset", type=int)
@click.option("--limit", default=100, help="API pagination limit", type=int)
@click.pass_obj
@pretty_print
def partner_endpoints(controller, partner, platform, hostname, offset, limit):
    """Get a list of endpoints from a partner"""
    with Spinner(description="Fetching endpoints from partner"):
        return controller.endpoints(
            partner=Control[partner],
            platform=platform,
            hostname=hostname,
            offset=offset,
            count=limit,
        )


@partner.command("deploy")
@click.confirmation_option(prompt="Are you sure?")
@click.argument(
    "partner", type=click.Choice([Control.CROWDSTRIKE.name], case_sensitive=False)
)
@click.option(
    "--host_ids",
    required=True,
    help="a list of host IDs to deploy to",
    multiple=True,
    default=[],
)
@click.pass_obj
@pretty_print
def partner_deploy(controller, partner, host_ids):
    """Deploy probes to hosts associated to a partner"""
    with Spinner(description="Deploying probes to hosts"):
        return controller.deploy(partner=Control[partner], host_ids=host_ids)


@partner.command("reports")
@click.argument(
    "partner", type=click.Choice([Control.CROWDSTRIKE.name], case_sensitive=False)
)
@click.option("-t", "--test_id", help="test to get reports for")
@click.pass_obj
@pretty_print
def partner_reports(controller, partner, test_id):
    """Get reports to a partner for a test"""
    with Spinner(description="Getting reports to partner"):
        return controller.list_reports(partner=Control[partner], test_id=test_id)


@partner.command("ioa-stats")
@click.option("-t", "--test_id", help="test to get IOA stats for")
@click.pass_obj
@pretty_print
def ioa_stats(controller, test_id):
    """Get IOA stats"""
    with Spinner(description="Getting IOA stats"):
        return controller.ioa_stats(test_id=test_id)


@partner.command("observed-detected")
@click.option("-t", "--test_id", help="test to get observed/detected stats for")
@click.option("-h", "--hours", help="number of hours to look back", type=int)
@click.pass_obj
@pretty_print
def observed_detected(controller, test_id, hours):
    """Get observed / detected stats"""
    with Spinner(description="Getting observed / detected stats"):
        return controller.observed_detected(test_id=test_id, hours=hours)


@partner.command("advisories")
@click.argument(
    "partner", type=click.Choice([Control.CROWDSTRIKE.name], case_sensitive=False)
)
@click.option("-s", "--start", help="start date for advisories")
@click.option("-o", "--offset", help="API pagination offset", type=int)
@click.option("-l", "--limit", help="API pagination limit", type=int)
@click.pass_obj
@pretty_print
def partner_advisories(controller, partner, start, offset, limit):
    """Get advisories provided by partner"""
    with Spinner(description="Getting partner advisories"):
        return controller.list_advisories(
            partner=Control[partner], start=start, offset=offset, limit=limit
        )
