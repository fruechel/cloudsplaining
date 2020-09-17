"""Runs aws iam get-authorization-details on all accounts specified in the aws credentials file, and stores them in
account-alias.json """
# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
import os
import json
import logging
from pathlib import Path
import boto3
import click
import click_log
from botocore.config import Config

logger = logging.getLogger()
click_log.basic_config(logger)


@click.command(
    short_help="Runs aws iam get-authorization-details on all accounts specified in the aws credentials "
    "file, and stores them in account-alias.json"
)
@click.option(
    "--profile",
    type=str,
    required=False,
    help="Specify 'all' to authenticate to AWS and analyze *all* existing IAM policies. Specify a non-default "
    "profile here. Defaults to the 'default' profile.",
)
@click.option(
    "--output",
    type=click.Path(exists=True),
    default=Path.cwd(),
    help="Path to store the output. Defaults to current directory.",
)
@click.option(
    "--include-non-default-policy-versions",
    is_flag=True,
    default=False,
    help="When downloading AWS managed policy documents, also include the non-default policy versions."
    " Note that this will dramatically increase the size of the downloaded file.",
)
@click_log.simple_verbosity_option(logger)
def download(profile, output, include_non_default_policy_versions):
    """
    Runs aws iam get-authorization-details on all accounts specified in the aws credentials file, and stores them in
    account-alias.json
    """
    default_region = "us-east-1"
    session_data = {"region_name": default_region}

    if profile:
        session_data["profile_name"] = profile
        output_filename = os.path.join(output, f"{profile}.json")
    else:
        output_filename = "default.json"

    results = get_account_authorization_details(session_data, include_non_default_policy_versions)

    if os.path.exists(output_filename):
        os.remove(output_filename)
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4, default=str)
        print(f"Saved results to {output_filename}")
    return 1




@click.command(
    short_help="Runs aws iam get-authorization-details on all accounts within an organisation and stores them in a file per account, using the name and account ID."
)
@click.option(
    "--payer-account-id",
    type=str,
    required=True,
    help="The account ID of the payer account which is the owner of the organisation. ListAccounts will be called against this account.",
)
@click.option(
    "--target-audit-role",
    type=str,
    required=True,
    help="The target role to assume in each account. Most have ListAccounts permission for payer account and GetAccountAuthorizationDetails on all accounts",
)
@click.option(
    "--output",
    type=click.Path(exists=True),
    default=Path.cwd(),
    help="Path to store the output. Defaults to current directory.",
)
@click.option(
    "--include-non-default-policy-versions",
    is_flag=True,
    default=False,
    help="When downloading AWS managed policy documents, also include the non-default policy versions."
    " Note that this will dramatically increase the size of the downloaded file.",
)
@click.option(
    "--overwrite-existing",
    is_flag=True,
    default=False,
    help="Re-download existing files rather than skipping them.",
)
@click.option(
    "--exclude-account",
    multiple=True,
    help="An account ID for which data shouldn't be downloaded even though it's part of the organisation. Can be specified multiple times.",
)
@click_log.simple_verbosity_option(logger)
def download_from_org(output, payer_account_id, target_audit_role, include_non_default_policy_versions, overwrite_existing, exclude_account):
    """
    Runs aws iam get-authorization-details on all accounts within an organisation and stores them in a file per account, using the name and account ID.
    """
    payer_session_data = get_cross_account_session_data(payer_account_id, target_audit_role)
    accounts = get_accounts_for_org(payer_session_data, exclude_account)
    for account in accounts.values():
        acc_name = account["Name"]
        acc_id = account["Id"]
        output_filename = os.path.join(output, f"auth-details-{acc_name}-{acc_id}.json")
        if not overwrite_existing and os.path.exists(output_filename):
            continue

        acc_session_data = get_cross_account_session_data(acc_id, target_audit_role)
        results = get_account_authorization_details(acc_session_data, include_non_default_policy_versions)

        with open(output_filename, "w") as file:
            json.dump(results, file, indent=4, default=str)
            print(f"Saved results to {output_filename}")


def get_accounts_for_org(payer_session_data, exclude_accounts=None):
    "Runs list-accounts to fetch all active accounts (minus excluded ones)"
    if exclude_accounts is None:
        exclude_accounts = []

    payer_session = boto3.Session(**payer_session_data)
    orgs = payer_session.client('organizations')
    paginator = orgs.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    accounts_data = []
    for page in page_iterator:
        accounts_data += page['Accounts']

    accounts = {}
    for acc in accounts_data:
        if acc['Status'] != 'ACTIVE':
            # Don't track suspended accounts
            continue
        if acc['Id'] in exclude_accounts:
            # Exclude this account from results
            continue
        accounts[acc['Id']] = {
            'Name': acc['Name'],
            'Id': acc['Id'],
            'Arn': acc['Arn'],
        }
    return accounts


def get_cross_account_session_data(account_id, role_name):
    target_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    # This is a thread-safe way of getting a new client
    sts = boto3.session.Session().client('sts')
    response = sts.assume_role(
        RoleArn=target_role_arn,
        RoleSessionName='cloudsplaining',
    )

    # Return session data
    return dict(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


def get_account_authorization_details(session_data, include_non_default_policy_versions):
    """Runs aws-iam-get-account-authorization-details"""
    session = boto3.Session(**session_data)
    config = Config(connect_timeout=5, retries={"max_attempts": 10})
    iam_client = session.client("iam", config=config)

    results = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    paginator = iam_client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User"]):
        # Always add inline user policies
        results["UserDetailList"].extend(page["UserDetailList"])
    for page in paginator.paginate(Filter=["Group"]):
        results["GroupDetailList"].extend(page["GroupDetailList"])
    for page in paginator.paginate(Filter=["Role"]):
        results["RoleDetailList"].extend(page["RoleDetailList"])
        # Ignore Service Linked Roles
        for policy in page["Policies"]:
            if policy["Path"] != "/service-role/":
                results["RoleDetailList"].append(policy)
    for page in paginator.paginate(Filter=["LocalManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                results["Policies"].append(policy)
    for page in paginator.paginate(Filter=["AWSManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                if include_non_default_policy_versions:
                    results["Policies"].append(policy)
                else:
                    policy_version_list = []
                    for policy_version in policy.get("PolicyVersionList"):
                        if policy_version.get("VersionId") == policy.get(
                            "DefaultVersionId"
                        ):
                            policy_version_list.append(policy_version)
                            break
                    entry = {
                        "PolicyName": policy.get("PolicyName"),
                        "PolicyId": policy.get("PolicyId"),
                        "Arn": policy.get("Arn"),
                        "Path": policy.get("Path"),
                        "DefaultVersionId": policy.get("DefaultVersionId"),
                        "AttachmentCount": policy.get("AttachmentCount"),
                        "PermissionsBoundaryUsageCount": policy.get(
                            "PermissionsBoundaryUsageCount"
                        ),
                        "IsAttachable": policy.get("IsAttachable"),
                        "CreateDate": policy.get("CreateDate"),
                        "UpdateDate": policy.get("UpdateDate"),
                        "PolicyVersionList": policy_version_list,
                    }
                    results["Policies"].append(entry)
    return results
