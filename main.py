import click
from password_manager import PasswordManager
import pyclip

@click.group()
def cli():
    """Password Manager CLI"""
    pass

@cli.command()
@click.option('--service', prompt='Service name', help='Name of the service')
@click.option('--username', prompt='Username', help='Username for the service')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for the service')
def add(service, username, password):
    """Add a new password entry"""
    master_password = click.prompt('Master password', hide_input=True)
    pm = PasswordManager()
    try:
        pm.save_password(service, username, password, master_password)
        click.echo(f"Password for {service} saved successfully!")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cli.command()
@click.option('--service', prompt='Service name', help='Name of the service')
def get(service):
    """Retrieve a password entry"""
    master_password = click.prompt('Master password', hide_input=True)
    pm = PasswordManager()
    try:
        entry = pm.get_password(service, master_password)
        click.echo(f"Username: {entry['username']}")
        click.echo(f"Password: {entry['password']}")
        if click.confirm('Copy password to clipboard?'):
            pyclip.copy(entry['password'])
            click.echo("Password copied to clipboard!")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cli.command()
def list():
    """List all stored services"""
    master_password = click.prompt('Master password', hide_input=True)
    pm = PasswordManager()
    try:
        services = pm.list_services(master_password)
        if services:
            click.echo("Stored services:")
            for service in services:
                click.echo(f"- {service}")
        else:
            click.echo("No services stored yet.")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

if __name__ == '__main__':
    cli()