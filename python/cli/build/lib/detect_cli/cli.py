import click

from detect_sdk.models.account import Account
from detect_cli.views.account import account
from detect_cli.views.configure import configure
from detect_cli.views.endpoints import endpoints
from detect_cli.views.manifest import manifest
from detect_cli.views.schedule import schedule


@click.group()
@click.pass_context
@click.option('--profile', default='default', help='detect keychain profile', show_default=True)
def cli(ctx, profile):
    ctx.obj = Account(profile=profile)


cli.add_command(account)
cli.add_command(configure)
cli.add_command(endpoints)
cli.add_command(schedule)
cli.add_command(manifest)


if __name__ == '__main__':
    cli()
