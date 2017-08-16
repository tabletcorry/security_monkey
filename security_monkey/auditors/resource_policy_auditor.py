#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.auditors.resource_policy_auditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <patrick@netflix.com>

"""
from security_monkey import app
from security_monkey.auditor import Auditor
from security_monkey.datastore import Account, Item, Technology

from policyuniverse.arn import ARN
from policyuniverse.policy import Policy
from policyuniverse.statement import Statement
import json
import dpath.util
from dpath.exceptions import PathNotFound
from collections import defaultdict


def add(to, key, value):
    if key in to:
        to[key].add(value)
    else:
        to[key] = set([value])

class ResourcePolicyAuditor(Auditor):
    
    OBJECT_STORE = defaultdict(dict)
    # NOT_PRINCIPAL = "An {singular} with 'NotPrincipal' must have a strong conditions block or it is Internet Accessible. "

    def __init__(self, accounts=None, debug=False):
        super(ResourcePolicyAuditor, self).__init__(accounts=accounts, debug=debug)
        self.policy_keys = ['Policy']

    def prep_for_audit(self):
        app.logger.info('INSIDE PREP_FOR_AUDIT')
        if not self.OBJECT_STORE:
            app.logger.info('ResourcePolicyAuditor Filling in OBJECT_STORE')
            self._load_s3_buckets()
            self._load_userids_usernames()
            self._load_accounts()
            self._load_vpcs()
            self._load_vpces()
            self._load_natgateways()

    @classmethod
    def _load_s3_buckets(cls):
        """Store the S3 bucket ARNs from all our accounts"""
        results = cls._load_related_items('s3')
        for item in results:
            add(cls.OBJECT_STORE['s3'], item.name, item.account.identifier)

    @classmethod
    def _load_vpcs(cls):
        """Store the VPC IDs. Also, extract & store network/NAT ranges."""
        results = cls._load_related_items('vpc')
        for item in results:
            add(cls.OBJECT_STORE['vpc'], item.config.get('id'), item.account.identifier)
            add(cls.OBJECT_STORE['cidr'], item.config.get('cidr_block'), item.account.identifier)

    @classmethod
    def _load_vpces(cls):
        """Store the VPC Endpoint IDs."""
        results = cls._load_related_items('endpoint')
        for item in results:
            add(cls.OBJECT_STORE['vpce'], item.config.get('id'), item.account.identifier)

    @classmethod
    def _load_natgateways(cls):
        """Store the NAT Gateway CIDRs."""
        results = cls._load_related_items('natgateway')
        for gateway in results:
            for address in gateway.config.get('nat_gateway_addresses', []):
                add(cls.OBJECT_STORE['cidr'], address['public_ip'], gateway.account.identifier)
                add(cls.OBJECT_STORE['cidr'], address['private_ip'], gateway.account.identifier)

    @classmethod
    def _load_userids_usernames(cls):
        """Store the UserIDs from all IAMUsers and IAMRoles.
        
        TODO: Determine if username conditions are suitable."""
        user_results = cls._load_related_items('iamuser')
        role_results = cls._load_related_items('iamrole')

        for item in user_results:
            add(cls.OBJECT_STORE['userid'], item.config.get('UserId'), item.account.identifier)
            add(cls.OBJECT_STORE['username'], item.config.get('UserName'), item.account.identifier)

        for item in role_results:
            add(cls.OBJECT_STORE['userid'], item.config.get('RoleId'), item.account.identifier)
            add(cls.OBJECT_STORE['username'], item.config.get('RoleName'), item.account.identifier)

    @classmethod
    def _load_accounts(cls):
        """Store the account IDs of all friendly/thirdparty accounts."""
        friendly_accounts = Account.query.filter(Account.third_party == False).all()
        third_party = Account.query.filter(Account.third_party == True).all()

        cls.OBJECT_STORE['ACCOUNTS']['FRIENDLY'] = set()
        for account in friendly_accounts:
            add(cls.OBJECT_STORE['ACCOUNTS'], 'FRIENDLY', account.identifier)
        
        cls.OBJECT_STORE['ACCOUNTS']['THIRDPARTY'] = set()
        for account in third_party:
            add(cls.OBJECT_STORE['ACCOUNTS'], 'THIRDPARTY', account.identifier)

    @staticmethod
    def _load_related_items(technology_name):
        query = Item.query.join((Technology, Technology.id == Item.tech_id))
        query = query.filter(Technology.name==technology_name)
        return query.all()

    def load_policies(self, item):
        """For a given item, return a list of all resource policies.
        
        Most items only have a single resource policy, typically found 
        inside the config with the key, "Policy".
        
        Some technologies have multiple resource policies.  A lambda function
        is an example of an item with multiple resource policies.
        
        The lambda function auditor can define a list of `policy_keys`.  Each
        item in this list is the dpath to one of the resource policies.
        
        The `policy_keys` defaults to ['Policy'] unless overriden by a subclass.
        
        Returns:
            list of Policy objects
        """

        if self.policy_keys == 'root':
            # SQS does not currently put Policy inside a policy block.
            # TODO: Refactor SQS to have Policy section
            return [Policy(item.config)]

        policies = list()
        for key in self.policy_keys:
            try:
                policy = dpath.util.values(item.config, key, separator='$')
                if isinstance(policy, list):
                    policies.extend([Policy(p) for p in policy])
                else:
                    policies.append(Policy(policy))
            except PathNotFound:
                continue
        return policies

    def record_internet_accessible_issue(self, item, actions):
        tag = "{singular} is Internet Accessible.".format(singular=self.i_am_singular)
        notes = "An {singular} ".format(singular=self.i_am_singular)
        notes += "with { 'Principal': { 'AWS': '*' } } must also have a strong condition block or it is Internet Accessible. "
        notes += "In this case, anyone is allowed to perform this action(s): "
        notes += json.dumps(list(actions))
        self.add_issue(10, tag, item, notes=notes)

    def record_friendly_cross_account_access_issue(self, item, who):
        tag = "{singular} provides friendly cross account access.".format(singular=self.i_am_singular)
        notes = 'Access provided to {category}:{who}.'.format(category=who.category, who=who.value)
        self.add_issue(0, tag, item, notes=notes)

    def record_unknown_cross_account_access_issue(self, item, who):
        tag = "{singular} provides cross account access to an unknown account.".format(singular=self.i_am_singular)
        notes = 'Access provided to {category}:{who}.'.format(category=who.category, who=who.value)
        self.add_issue(10, tag, item, notes=notes)

    def check_internet_accessible(self, item):
        """A resource policy is typically internet accessible if:
        
        The Policy contains a statement where:
        1) Effect: Allow, Principal: '*', weak or no mitigating conditions.
        2) Effect: Allow, Principal: Arn with wildcard account_number, weak or no mitigating conditions.
        3) Effect: Allow, NotPrincipal Used, weak or no mitigating conditions.
        
        Error Conditions:
        1) Unparseable ARN in Principal 
        2) Unparseable ARN in Condition block.
        """
        policies = self.load_policies(item)
        for policy in policies:
            if policy.is_internet_accessible():
                # TODO - Issue should specify which policy is internet accessible if multiple are present.
                self.record_internet_accessible_issue(item, policy.internet_accessible_actions())

    def check_friendly_cross_account(self, item):
        policies = self.load_policies(item)
        for policy in policies:
            for who in policy.whos_allowed():
                if 'FRIENDLY' in self.inspect_who(who, item):
                    self.record_friendly_cross_account_access_issue(item, who)

    def check_unknown_cross_account(self, item):
        policies = self.load_policies(item)
        for policy in policies:
            for who in policy.whos_allowed():
                if 'UNKNOWN' in self.inspect_who(who, item):
                    self.record_unknown_cross_account_access_issue(item, who)

    def inspect_who(self, who, item):
        """A who could be:
        
        - ARN
        - Account Number
        - UserID
        - UserName
        - CIDR
        - VPC
        - VPCE
        
        Determine if the who is in our current account.
        
        Return:
            'SAME' - The who is in our same account.
            'FRIENDLY' - The who is in an account Security Monkey knows about.
            'UNKNOWN' - The who is in an account Security Monkey does not know about.
        """
        same = item.account_number
        same = Account.query.filter(Account.identifier == item.account_number).first()
        
        if who.category in ['arn', 'principal']:
            return self.inspect_who_arn(who.value, same)
        if who.category == 'account':
            return set([self.inspect_who_account(who.value, same)])
        if who.category == 'userid':
            return self.inspect_who_userid(who.value, same)
        if who.category == 'username':
            return self.inspect_who_username(who.value, same)
        if who.category == 'cidr':
            return self.inspect_who_cidr(who.value, same)
        if who.category == 'vpc':
            return self.inspect_who_vpc(who.value, same)
        if who.category == 'vpce':
            return self.inspect_who_vpce(who.value, same)
        
        return 'ERROR'
    
    def inspect_who_arn(self, arn, same):
        arn = ARN(arn)
        if arn.error:
            self.record_arn_parse_issue()

        if arn.tech == 's3':
            return self.inspect_who_s3(arn.name, same)

        return set([self.inspect_who_account(arn.account_number, same)])

    def inspect_who_account(self, account_number, same):
        if account_number == same.identifier:
            return 'SAME'
        if account_number in self.OBJECT_STORE['ACCOUNTS']['FRIENDLY']:
            return 'FRIENDLY'
        if account_number in self.OBJECT_STORE['ACCOUNTS']['THIRDPARTY']:
            return 'THIRDPARTY'
        return 'UNKNOWN'

    def inspect_who_username(self, user_name, same):
        return self.inspect_who_generic('username', user_name, same)

    def inspect_who_s3(self, bucket_name, same):
        return self.inspect_who_generic('s3', bucket_name, same)

    def inspect_who_userid(self, userid, same):
        return self.inspect_who_generic('userid', userid.split(':')[0], same)

    def inspect_who_vpc(self, vpcid, same):
        return self.inspect_who_generic('vpc', vpcid, same)

    def inspect_who_vpce(self, vpcid, same):
        return self.inspect_who_generic('vpce', vpcid, same)

    def inspect_who_cidr(self, cidr, same):
        return self.inspect_who_generic('cidr', cidr, same)
    
    def inspect_who_generic(self, key, item, same):
        if item in self.OBJECT_STORE[key]:
            values = set()
            for account in self.OBJECT_STORE[key][item]:
                values.add(self.inspect_who_account(account, same))
            return values
        return set(['UNKNOWN'])
