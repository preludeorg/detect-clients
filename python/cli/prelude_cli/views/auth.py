import click

from prelude_cli.views.shared import Spinner, pretty_print


@click.group()
@click.pass_context
def auth(ctx):
    """Authentication"""
    pass


@auth.command("login")
@click.option("-p", "--password", required=True, type=str)
@click.pass_obj
@pretty_print
def login(account, password):
    """Login using your password"""
    with Spinner(description="Logging in and saving tokens"):
        account.password_login(password)
    return [], "Login successful"


@auth.command("refresh")
@click.pass_obj
@pretty_print
def refresh(account):
    """Refresh your tokens"""
    with Spinner(description="Refreshing tokens"):
        account.refresh_tokens()
    return [], "New access tokens saved"
