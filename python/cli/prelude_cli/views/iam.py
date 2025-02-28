import click

from datetime import datetime, timedelta, timezone

from prelude_sdk.models.codes import AuditEvent, Mode, Permission
from prelude_cli.views.shared import Spinner, pretty_print
from prelude_sdk.controllers.iam_controller import IAMController


@click.group()
@click.pass_context
def iam(ctx):
    """Prelude account management"""
    ctx.obj = IAMController(account=ctx.obj)


@iam.command("account")
@click.pass_obj
@pretty_print
def describe_account(controller):
    """Get account details"""
    with Spinner(description="Fetching account details"):
        return controller.get_account()


@iam.command("list-accounts")
@click.pass_obj
@pretty_print
def describe_account(controller):
    """List all accounts for your user"""
    with Spinner(description="Fetching all accounts for your user"):
        return controller.list_accounts()


@iam.command("reset-password")
@click.argument("email")
@click.pass_obj
@pretty_print
def reset_password(controller, email):
    """Reset a user's password"""
    with Spinner(description="Resetting password"):
        return controller.reset_password(email=email)


@iam.command("purge")
@click.confirmation_option(prompt="Are you sure?")
@click.pass_obj
@pretty_print
def purge(controller):
    """Delete your account"""
    with Spinner(description="Purging account from existence"):
        return controller.purge_account()


@iam.command("update-account")
@click.option(
    "-m",
    "--mode",
    help="provide a mode",
    default=None,
    show_default=False,
    type=click.Choice([m.name for m in Mode], case_sensitive=False),
)
@click.option(
    "-c",
    "--company",
    help="provide your associated company",
    default=None,
    show_default=False,
    type=str,
)
@click.option(
    "-s",
    "--slug",
    help="provide a unique human-readable identifier for your account",
    default=None,
    show_default=False,
    type=str,
)
@click.pass_obj
@pretty_print
def update_account(controller, mode, company, slug):
    """Update an account"""
    with Spinner(description="Updating account information"):
        return controller.update_account(
            mode=Mode[mode] if mode else None, company=company, slug=slug
        )


@iam.command("attach-oidc")
@click.argument(
    "issuer", type=click.Choice(["google", "azure", "okta"], case_sensitive=False)
)
@click.option("--client_id", required=True, help="Client ID")
@click.option("--client_secret", required=True, help="Client secret")
@click.option("--oidc_config_url", required=True, help="Configuration endpoint")
@click.pass_obj
@pretty_print
def attach_oidc(controller, issuer, client_id, client_secret, oidc_config_url):
    """Attach OIDC to an account"""
    with Spinner(description="Attaching OIDC"):
        return controller.attach_oidc(
            client_id=client_id,
            client_secret=client_secret,
            issuer=issuer,
            oidc_url=oidc_config_url,
        )


@iam.command("detach-oidc")
@click.confirmation_option(prompt="Are you sure?")
@click.pass_obj
@pretty_print
def detach_oidc(controller):
    """Detach OIDC to an account"""
    with Spinner(description="Detaching OIDC"):
        return controller.detach_oidc()


@iam.command("oidc-name")
@click.argument("slug")
@click.pass_obj
@pretty_print
def get_oidc_name(controller, slug):
    """Get OIDC provider name from organization slug"""
    with Spinner(description="Fetching OIDC provider name"):
        return controller.get_oidc_name(slug=slug)


@iam.command("invite-user")
@click.option(
    "-p",
    "--permission",
    help="user permission level",
    default=Permission.EXECUTIVE.name,
    type=click.Choice(
        [
            p.name
            for p in Permission
            if p not in [Permission.INVALID, Permission.SERVICE, Permission.SUPPORT]
        ],
        case_sensitive=False,
    ),
    show_default=True,
)
@click.option(
    "-n", "--name", help="name of user", default=None, show_default=False, type=str
)
@click.option(
    "-o", "--oidc", help="OIDC app name", default=None, show_default=False, type=str
)
@click.argument("email")
@click.pass_obj
@pretty_print
def invite_user(controller, permission, name, oidc, email):
    """Invite a new user to your account"""
    with Spinner(description="Inviting new user"):
        data = controller.invite_user(
            email=email,
            oidc=oidc,
            permission=Permission[permission],
            name=name,
        )
    msg = "New user must check their email to verify their account"
    return data, msg


@iam.command("create-service-user")
@click.argument("email")
@click.pass_obj
@pretty_print
def invite_user(controller, email):
    """Create a new service user in your account"""
    with Spinner(description="Creating new service user"):
        data = controller.create_service_user(email=email)
    msg = "New user must check their email to verify their account"
    return data, msg


@iam.command("update-user")
@click.option("-n", "--name", help="name of user", type=str)
@click.pass_obj
@pretty_print
def update_user(controller, name):
    """Update your user information"""
    with Spinner(description="Updating user"):
        return controller.update_user(name=name)


@iam.command("update-account-user")
@click.option(
    "-p",
    "--permission",
    help="user permission level",
    default=Permission.EXECUTIVE.name,
    type=click.Choice(
        [
            p.name
            for p in Permission
            if p not in [Permission.INVALID, Permission.SERVICE, Permission.SUPPORT]
        ],
        case_sensitive=False,
    ),
    show_default=True,
)
@click.option(
    "-o", "--oidc", help="OIDC app name", default=None, show_default=False, type=str
)
@click.argument("email")
@click.pass_obj
@pretty_print
def update_account_user(controller, permission, oidc, email):
    """Update a user in your account"""
    with Spinner(description="Updating account user"):
        return controller.update_account_user(
            email=email, oidc=oidc, permission=permission
        )


@iam.command("remove-user")
@click.confirmation_option(prompt="Are you sure?")
@click.option(
    "-o", "--oidc", help="OIDC app name", default=None, show_default=False, type=str
)
@click.argument("email")
@click.pass_obj
@pretty_print
def delete_user(controller, oidc, email):
    """Remove a user from your account"""
    with Spinner(description="Removing user"):
        return controller.remove_user(email=email, oidc=oidc)


@iam.command("purge-user")
@click.confirmation_option(prompt="Are you sure?")
@click.pass_obj
@pretty_print
def delete_user(controller):
    """Remove your user from all accounts and purge user data"""
    with Spinner(description="Purging user"):
        return controller.purge_user()


@iam.command("logs")
@click.option(
    "-d", "--days", help="days back to search from today", default=7, type=int
)
@click.option(
    "-l", "--limit", help="limit the number of results", default=1000, type=int
)
@click.pass_obj
@pretty_print
def logs(controller, days, limit):
    """Get audit logs"""
    with Spinner(description="Fetching logs"):
        return controller.audit_logs(days=days, limit=limit)
