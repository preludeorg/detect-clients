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


@iam.command("migrate")
@click.pass_obj
@pretty_print
def migrate(controller):
    with Spinner(description="Migrating keychain"):
        return controller.migrate()


@iam.command("create-account")
@click.pass_obj
@pretty_print
@click.confirmation_option(
    prompt="Overwrite local account credentials for selected profile?"
)
def register_account(controller):
    """Register a new account"""
    email = click.prompt("Enter your email")
    company = click.prompt("Enter your associated company")
    name = click.prompt("(Optional) Enter your name", default="", show_default=False)
    slug = click.prompt(
        "(Optional) Enter an unique human-readable identifier for your account",
        default="",
        show_default=False,
    )
    with Spinner(description="Creating new account"):
        data = controller.new_account(
            user_email=email, company=company, user_name=name, slug=slug
        )
    return data, "Check your email to verify your account"


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
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            oidc_config_url=oidc_config_url,
        )


@iam.command("detach-oidc")
@click.confirmation_option(prompt="Are you sure?")
@click.pass_obj
@pretty_print
def detach_oidc(controller):
    """Detach OIDC to an account"""
    with Spinner(description="Detaching OIDC"):
        return controller.detach_oidc()


@iam.command("account")
@click.pass_obj
@pretty_print
def describe_account(controller):
    """Get account details"""
    with Spinner(description="Fetching account details"):
        return controller.get_account()


@iam.command("create-user")
@click.option(
    "-d", "--days", help="days this user will remain active", default=365, type=int
)
@click.option(
    "-p",
    "--permission",
    help="user permission level",
    default=Permission.SERVICE.name,
    type=click.Choice(
        [p.name for p in Permission if p != Permission.INVALID], case_sensitive=False
    ),
    show_default=True,
)
@click.option(
    "-n", "--name", help="name of user", default=None, show_default=False, type=str
)
@click.option("-o", "--oidc", help="whether user must login via SSO", is_flag=True)
@click.argument("email")
@click.pass_obj
@pretty_print
def create_user(controller, days, permission, name, oidc, email):
    """Create a new user in your account"""
    with Spinner(description="Creating new user"):
        data = controller.create_user(
            email=email,
            permission=Permission[permission],
            name=name,
            expires=datetime.now(timezone.utc) + timedelta(days=days),
            oidc=oidc,
        )
    msg = "New user must check their email to verify their account"
    return data, msg if permission != Permission.SERVICE.name else None


@iam.command("reset-password")
@click.argument("email")
@click.option(
    "-a",
    "--account",
    help="override the profile account id",
    default=None,
    show_default=False,
    type=str,
)
@click.pass_obj
@pretty_print
def reset_password(controller, email, account):
    """Reset a user's password"""
    with Spinner(description="Resetting password"):
        controller.reset_password(email=email, account_id=account)

    token = click.prompt(
        "Check your email for the reset token.\nEnter your reset token", type=str
    )
    with Spinner(description="Retrieving new password"):
        return controller.verify_user(token=token)


@iam.command("update-user")
@click.option(
    "-d", "--days", help="days from now this user will remain active", type=int
)
@click.option(
    "-p",
    "--permission",
    help="user permission level",
    type=click.Choice(
        [
            p.name
            for p in Permission
            if p not in [Permission.INVALID, Permission.SERVICE]
        ],
        case_sensitive=False,
    ),
)
@click.option("-n", "--name", help="name of user", type=str)
@click.option("--oidc/--no-oidc", help="whether user must login via SSO", default=None)
@click.argument("email")
@click.pass_obj
@pretty_print
def update_user(controller, days, permission, name, oidc, email):
    """Update a user in your account"""
    with Spinner(description="Updating user"):
        return controller.update_user(
            email=email,
            permission=Permission[permission] if permission else None,
            name=name,
            expires=datetime.now(timezone.utc) + timedelta(days=days) if days else None,
            oidc=oidc,
        )


@iam.command("delete-user")
@click.confirmation_option(prompt="Are you sure?")
@click.argument("handle")
@click.pass_obj
@pretty_print
def delete_user(controller, handle):
    """Remove a user from your account"""
    with Spinner(description="Deleting user"):
        return controller.delete_user(handle=handle)


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


@iam.command("subscribe")
@click.argument(
    "event",
    type=click.Choice(
        [e.name for e in AuditEvent if e != AuditEvent.INVALID], case_sensitive=False
    ),
)
@click.pass_obj
@pretty_print
def subscribe(controller, event):
    """Subscribe to email notifications for an event"""
    with Spinner(description="Subscribing"):
        return controller.subscribe(event=AuditEvent[event])


@iam.command("unsubscribe")
@click.argument(
    "event",
    type=click.Choice(
        [e.name for e in AuditEvent if e != AuditEvent.INVALID], case_sensitive=False
    ),
)
@click.pass_obj
@pretty_print
def unsubscribe(controller, event):
    """Unsubscribe to email notifications for an event"""
    with Spinner(description="Unsubscribing"):
        return controller.unsubscribe(event=AuditEvent[event])


@iam.command("accept-terms", hidden=True)
@click.argument("name", type=str, required=True)
@click.option("-v", "--version", type=int, required=True)
@click.pass_obj
@pretty_print
def accept_terms(controller, name, version):
    """Accept terms and conditions"""
    with Spinner(description="Accepting terms and conditions"):
        return controller.accept_terms(name=name, version=version)


@iam.command("purge")
@click.confirmation_option(prompt="Are you sure?")
@click.pass_obj
@pretty_print
def purge(controller):
    """Delete your account"""
    with Spinner(description="Purging account from existence"):
        return controller.purge_account()
