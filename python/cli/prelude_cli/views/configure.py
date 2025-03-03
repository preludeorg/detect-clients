import click


@click.command()
@click.pass_obj
def configure(account):
    """Configure your local keychain"""
    profile = click.prompt(
        "Enter the profile name",
        default=account.profile or "default",
        show_default=True,
    )
    hq = click.prompt("Enter the Prelude API", default=account.hq, show_default=True)
    account_id = click.prompt("Enter your account ID")
    handle = click.prompt("Enter your user handle (email)")
    account.keychain.configure_keychain(
        account=account_id, handle=handle, hq=hq, profile=profile
    )
    click.secho("Credentials saved", fg="green")
