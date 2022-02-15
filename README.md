# aws-service-catalog-pp-migration
Service Catalog provisioned products migration


#### Collect provisioned product details across multiple accounts

**file_name:** functions/collect_pp_details.py

usage: collect_pp_details.py [-a|-r]

Return all provisioned products across accounts.

optional arguments:
  -h, --help            show this help message and exit
  -a ACCOUNTS, --accounts ACCOUNTS
                        Comma seperated list of accounts
  -r EXEC_ROLE, --exec_role EXEC_ROLE
                        Cross account execution role to use. Default: SCListCrossAccountRole
