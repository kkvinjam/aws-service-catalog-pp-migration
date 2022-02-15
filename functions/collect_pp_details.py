#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

'''
This lamdba checks for application tag for existing cloudformation templates
and auto registers the stacks with AppRegistry.
'''

import logging
import argparse
import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
SC = boto3.client('servicecatalog')
STS = boto3.client('sts')


def assume_role(account_id, role):
    '''
    Return a session in the target account using Control Tower Role
    '''

    try:
        curr_account = STS.get_caller_identity()['Account']
        if curr_account != account_id:
            part = STS.get_caller_identity()['Arn'].split(":")[1]
            role_arn = 'arn:' + part + ':iam::' + account_id + ':role/' + role
            ses_name = str(account_id + '-' + role)
            response = STS.assume_role(RoleArn=role_arn,
                                       RoleSessionName=ses_name)
            credentials = response['Credentials']
            sts_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
                )
            LOGGER.info('Assumed session for %s, %s', account_id, role)
            return sts_session
    except ClientError as exe:
        LOGGER.error('Unable to assume role')
        raise exe


def get_account_id():
    '''
    Return the AWS AccountId where the command is executed
    '''
    result = None

    try:
        result = STS.get_caller_identity()['Account']
    except ClientError as exe:
        LOGGER.error('Unable to retrive account id: %s', str(exe))

    return result


def return_status(output, status_code=200):
    '''
    Return true is response data matches with status_code
    '''

    if 'ResponseMetadata' in output:
        status = output['ResponseMetadata']['HTTPStatusCode']
        if status != status_code:
            LOGGER.error('Unexpected Status: %s', status)


def list_all_provisioned_products(context, level='Account', p_filter=None):
    '''
    List all provisioned products with in an account/region
    filter={"SearchQuery":["status:AVAILABLE"]}
    context.list_all_provisioned_products(filter={"SearchQuery":["productId:prod-1234567890123"]}
    '''

    output = dict()
    a_filter = {"Key": level, "Value": "self"}

    try:
        if p_filter:
            output = context.search_provisioned_products(
                AccessLevelFilter=a_filter, Filters=p_filter)
        else:
            output = context.search_provisioned_products(
                AccessLevelFilter=a_filter)
    except ClientError as exe:
        LOGGER.error('Unable to get provisioned products list: %s', str(exe))

    return_status(output)

    return output


def list_prov_prod_summary(context):
    '''
    Return summary of provisioned products
    '''

    result = list()

    collection = ['Id', 'Name', 'ProvisioningArtifactId',
                  'Status', 'ProductId', 'ProductName']
    pp_list = list_all_provisioned_products(context)
    if 'ProvisionedProducts' in pp_list:
        for item in pp_list['ProvisionedProducts']:
            output = dict()
            for key in collection:
                output[key] = item[key]
            result.append(output)
    return result


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(prog='collect_pp_details.py',
                                     usage='%(prog)s [-a|-r]',
                                     description='Return all provisioned \
                                         products across accounts.')
    PARSER.add_argument("-a", "--accounts", type=str,
                        help="Comma seperated list of accounts")
    PARSER.add_argument("-r", "--exec_role", type=str,
                        default='SCListCrossAccountRole',
                        help="Cross account execution role to use. \
                            Default: SCListCrossAccountRole")

    ARGS = PARSER.parse_args()
    EXEC_ROLE = ARGS.exec_role
    HUB_ID = get_account_id()
    ACCOUNTS = ARGS.accounts
    OUTPUT = dict()

    if ARGS.accounts:
        ACCOUNTS = ARGS.accounts.split(',')
        ACCOUNTS.append(HUB_ID)
    else:
        ACCOUNTS = [HUB_ID]

    for account in ACCOUNTS:
        if account != HUB_ID:
            remote_session = assume_role(account, EXEC_ROLE)
            sc_context = remote_session.client('servicecatalog')
            OUTPUT[account] = list_prov_prod_summary(sc_context)
        else:
            OUTPUT[account] = list_prov_prod_summary(SC)

    print(OUTPUT)
