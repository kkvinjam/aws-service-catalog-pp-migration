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
Script to switch the product-id onwership from
ORIGIN productId to TARGET productId.

Highlevel Steps:
1. Get list of all provisioned products for the ORIGIN productId
2. Switch all provisioned products from ORIGIN to TARGET productId
2a. Terminate the SC provisioned product with resources detached.
2b. Import the provisioned product with Target ProductID, latest PAId
'''

import logging
import argparse
from time import sleep
import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
SC = boto3.client('servicecatalog')
STS = boto3.client('sts')


def get_account_id(context):
    '''
    Return the AWS AccountId where the command is executed
    '''
    result = None

    try:
        result = context.get_caller_identity()['Account']
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


def get_product_id(context, prod_name):
    '''
    Return product id of a given product name.
    Return None if more than two products found with same name
    '''

    prod_id = None
    try:
        result = context.describe_product(Name=prod_name)
        prod_id = result['ProductViewSummary']['ProductId']
    except ClientError as exe:
        LOGGER.error('Unable to get product id: %s', str(exe))

    return prod_id


def get_product_name(context, port_id):
    '''
    Return product id of a given product name.
    Return None if more than two products found with same name
    '''

    prod_name = None
    try:
        result = context.describe_product(Id=port_id)
        prod_name = result['ProductViewSummary']['Name']
    except ClientError as exe:
        LOGGER.error('Unable to get product name: %s', str(exe))

    return prod_name


def list_all_products_per_portfolio(context, prod_name):
    '''
    Return list of portfolios
    '''

    output = list()
    retry_count = 0
    throttle_retry = True
    search = dict()
    search["FullTextSearch"] = [prod_name]
    while throttle_retry and retry_count < 5:
        try:
            paginator = context.get_paginator('search_products_as_admin')
            page_iterator = paginator.paginate(Filters=search)
            throttle_retry = False
        except ClientError as exe:
            LOGGER.error('Failed to list portfolios:%s', str(exe))

    for page in page_iterator:
        output += page['ProductViewDetails']

    return output


def list_products_per_potfolio(context):
    '''
    Return list of portfolios
    '''

    output = list()
    retry_count = 0
    throttle_retry = True

    while throttle_retry and retry_count < 5:
        try:
            paginator = context.get_paginator('search_products_as_admin')
            page_iterator = paginator.paginate()
            throttle_retry = False
        except ClientError as exe:
            LOGGER.error('Failed to list portfolios:%s', str(exe))

    for page in page_iterator:
        output += page['ProductViewDetails']

    return output


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
            output = context.search_provisioned_products(AccessLevelFilter=a_filter,
                                                         Filters=p_filter)
        else:
            output = context.search_provisioned_products(AccessLevelFilter=a_filter)
    except ClientError as exe:
        LOGGER.error('Unable to get provisioned products list: %s', str(exe))

    return_status(output)

    return output


def list_all_pp_per_product(context, prod_id):
    '''
    List all provisioned products with in an account/region
    filter={"SearchQuery":["status:AVAILABLE"]}
    context.list_all_provisioned_products(filter={"SearchQuery":["productId:prod-1234567890123"]}
    '''

    output = dict()
    a_filter = {"Key": "Account", "Value": "self"}
    qry_string = "productId:" + prod_id
    p_filter = {"SearchQuery":[qry_string]}

    try:
        output = context.search_provisioned_products(AccessLevelFilter=a_filter,
                                                     Filters=p_filter)
    except ClientError as exe:
        LOGGER.error('Unable to get provisioned products list: %s', str(exe))

    return_status(output)

    return output


def get_cft_arn(context, pp_id):
    '''
    Return the Cloudformation Arn of a provisioned product
    context.list_all_provisioned_products(filter={"SearchQuery":["id:pp-1234567890123"]}
    '''

    output = {'ProvisionedProducts':[]}
    cft_arn = None
    a_filter = {"Key": "Account", "Value": "self"}
    qry_string = "id:" + pp_id
    p_filter = {"SearchQuery":[qry_string]}

    try:
        output = context.search_provisioned_products(AccessLevelFilter=a_filter,
                                                     Filters=p_filter)
    except ClientError as exe:
        LOGGER.error('Unable to get provisioned products list: %s', str(exe))

    return_status(output)

    pp_info = output['ProvisionedProducts']

    if len(pp_info) > 0 and'PhysicalId' in pp_info[0]:
        cft_arn = pp_info[0]['PhysicalId']

    return cft_arn


def list_prov_prod_summary(context):
    '''
    Return summary of provisioned products
    '''

    result = list()

    collection = ['Id', 'Name', 'ProvisioningArtifactId',
                  'Status', 'ProductId', 'ProductName']
    prov_prod_list = list_all_provisioned_products(context)
    if 'ProvisionedProducts' in prov_prod_list:
        for item in prov_prod_list['ProvisionedProducts']:
            output = dict()
            for key in collection:
                output[key] = item[key]
            result.append(output)
    return result


def get_latest_pa_id(context, prod_id):
    '''
    Return the latest provisioning artifact id value
    '''

    pa_id = None

    try:
        result = context.describe_product(Id=prod_id)
        pa_id = result['ProvisioningArtifacts'][0]['Id']
    except ClientError as exe:
        LOGGER.error('Unable to get provisioning artifact id: %s', str(exe))

    return pa_id


def detach_provisioned_product(context, pp_id):
    '''
    Detach a provisioned product
    '''

    result = None

    try:
        result = context.terminate_provisioned_product(
            ProvisionedProductId=pp_id, RetainPhysicalResources=True)
    except ClientError as exe:
        LOGGER.error('Unable to detach the provisioned product: %s', str(exe))

    return result


def import_provisioned_product(context, prod_id, pa_id, pp_namer, cft_arn):
    '''
    Import a provisioned product
    '''

    result = False

    try:
        result = context.import_as_provisioned_product(ProductId=prod_id,
                    ProvisioningArtifactId=pa_id,
                    ProvisionedProductName=pp_namer,
                    PhysicalId=cft_arn)
    except ClientError as exe:
        LOGGER.error('Unable to import a provisioned product: %s', str(exe))

    return result


def get_prov_prod_name(context, pp_id):
    '''
    Return the cloudformation stack name of a provisioned product
    '''

    pp_namer = None

    try:
        result = context.describe_provisioned_product(Id=pp_id)
        pp_namer = result['ProvisionedProductDetail']['Name']
    except ClientError as exe:
        LOGGER.error('Unable to get provisioned product name: %s', str(exe))

    return pp_namer


def does_cft_exists(context, cft_arn):
    '''
    Return True if the CloudFormation template exists
    '''

    result = False

    try:
        result = context.describe_stacks(StackName=cft_arn)
    except ClientError as exe:
        LOGGER.info('Stack NOT FOUND: %s', str(exe))

    return result


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(prog='switch_pp_between_products.py',
                                     usage='%(prog)s -o -d [-a|-r]',
                                     description='Switch the provisioned product \
                                         between two products.')
    PARSER.add_argument("-o", "--origin", type=str, required=True, help="Origin ProductId")
    PARSER.add_argument("-t", "--target", type=str, required=True, help="Target ProductId")
    PARSER.add_argument("-a", "--accounts", type=str,
                        help="Comma seperated list of accounts")
    PARSER.add_argument("-r", "--exec_role", type=str,
                        default='SCListCrossAccountRole',
                        help="Cross account execution role to use. \
                            Default: SCListCrossAccountRole")

    ARGS = PARSER.parse_args()
    EXEC_ROLE = ARGS.exec_role
    ORIGIN_PID = ARGS.origin
    TARGET_PID = ARGS.target
    HUB_ID = get_account_id(STS)
    ACCOUNTS = ARGS.accounts
    OUTPUT = dict()

    if ARGS.accounts:
        ACCOUNTS = ARGS.accounts.split(',')
    else:
        ACCOUNTS = [HUB_ID]

    for account in ACCOUNTS:
        if account != HUB_ID:
            remote_session = assume_role(account, EXEC_ROLE)
            sc_context = remote_session.client('servicecatalog')
            sts_context = remote_session.client('sts')
        else:
            sc_context = SC.client('servicecatalog')
            sts_context = SC.client('sts')

        acct_id = get_account_id(sts_context)
        pp_list = list_all_pp_per_product(sc_context, ORIGIN_PID)

        for pp in pp_list['ProvisionedProducts']:

            pp_name = pp['Name']
            pp_id = pp['Id']
            #LOGGER.info('Start Import %s, %s in Account %s',
            #                pp_name, pp_id, acct_id)
            print(f'\nStart Importing {pp_name}, {pp_id} to {acct_id}')
            cft_pid = get_cft_arn(sc_context, pp_id)
            print(f'\nDetaching {pp_name}, {pp_id}')
            import_status = detach_provisioned_product(sc_context, pp['Id'])
            sleep(10)
            if import_status:
                prov_artifact_id = get_latest_pa_id(sc_context, TARGET_PID)
                print(f'\nImporting {pp_name} to {TARGET_PID}')
                import_provisioned_product(sc_context, TARGET_PID,
                                    prov_artifact_id, pp['Name'], cft_pid)
            else:
                print('Detaching failed hence stoping import')
