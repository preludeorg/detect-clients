import click

from rich import print_json

from prelude_cli.views.shared import handle_api_error, Spinner
from prelude_sdk.controllers.partner_controller import PartnerController


@click.group()
@click.pass_context
def partner(ctx):
    """ Partner system commands """
    ctx.obj = PartnerController(account=ctx.obj)


@partner.command('attach')
@click.argument('partner-code')
@click.option('--api', required=True, help='API endpoint of the partner')
@click.option('--user', default='', help='user identifier')
@click.option('--secret', default='', help='secret for OAUTH use cases')
@click.pass_obj
@handle_api_error
def attach_partner(controller, partner_code, api, user, secret):
    """ Attach an EDR to Detect """
    with Spinner(description='Attaching partner'):
        data = controller.attach(partner_code=partner_code, api=api, user=user, secret=secret)
    print_json(data=data)


@partner.command('detach')
@click.confirmation_option(prompt='Are you sure?')
@click.argument('partner-code')
@click.pass_obj
@handle_api_error
def detach_partner(controller, partner_code):
    """ Detach an existing partner from your account """
    with Spinner(description='Detaching partner'):
        controller.detach(partner_code=partner_code)


@partner.command('endpoints')
@click.argument('partner-code')
@click.option('--platform', required=True, help='platform name (e.g. "windows")', type=click.Choice(['windows', 'linux', 'darwin'], case_sensitive=False))
@click.option('--hostname', default='', help='hostname pattern (e.g. "mycompany-c24oi444")')
@click.option('--offset', default=0, help='API pagination offset', type=int)
@click.pass_obj
@handle_api_error
def partner_endpoints(controller, partner_code, platform, hostname, offset):
    """ Get a list of endpoints from a partner """
    with Spinner(description='Fetching endpoints from partner'):
        data = controller.endpoints(partner_code=partner_code, platform=platform, hostname=hostname, offset=offset)
    print_json(data=data)


@partner.command('deploy')
@click.confirmation_option(prompt='Are you sure?')
@click.argument('partner-code')
@click.option('--host_ids', required=True, help='a list of host IDs to deploy to', multiple=True, default=[])
@click.pass_obj
@handle_api_error
def partner_deploy(controller, partner_code, host_ids):
    """ Deploy probes to hosts associated to a partner """
    with Spinner(description='Deploying probes to hosts'):
        data = controller.deploy(partner_code=partner_code, host_ids=host_ids)
    print_json(data=data)
