import click

from prelude_cli.views.auth import auth
from prelude_cli.views.build import build
from prelude_cli.views.configure import configure
from prelude_cli.views.detect import detect
from prelude_cli.views.generate import generate
from prelude_cli.views.iam import iam
from prelude_cli.views.jobs import jobs
from prelude_cli.views.partner import partner
from prelude_cli.views.scm import scm
from prelude_sdk.models.account import Account, Keychain


def complete_profile(ctx, param, incomplete):
    return [x for x in Keychain().read_keychain() if x.startswith(incomplete)]


@click.group(invoke_without_command=True)
@click.version_option()
@click.pass_context
@click.option(
    "--profile",
    default="default",
    help="The prelude keychain profile to use",
    show_default=True,
    shell_complete=complete_profile,
)
@click.option("--account", default=None, help="Account ID")
@click.option("--handle", default=None, help="User handle (email)")
@click.option("--hq", default="https://api.us1.preludesecurity.com", help="Prelude API")
@click.option(
    "--token",
    default=None,
    help="ID token. Must also provide account, handle, and hq if used.",
)
@click.option
def cli(ctx, profile, account, handle, hq, token):
    if profile:
        ctx.obj = Account.from_keychain(profile=profile)
    elif all([account, handle, hq, token]):
        ctx.obj = Account.from_token(account, handle, token, hq=hq)
    else:
        raise Exception(
            "Please provide either a profile or account, handle, hq, and token"
        )
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


cli.add_command(auth)
cli.add_command(build)
cli.add_command(configure)
cli.add_command(detect)
cli.add_command(generate)
cli.add_command(iam)
cli.add_command(jobs)
cli.add_command(partner)
cli.add_command(scm)


if __name__ == "__main__":
    cli()
