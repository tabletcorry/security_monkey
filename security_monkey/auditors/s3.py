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
.. module: security_monkey.auditors.s3
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""
from security_monkey.auditors.resource_policy_auditor import ResourcePolicyAuditor
from security_monkey.watchers.s3 import S3
from security_monkey.datastore import Account


class S3Auditor(ResourcePolicyAuditor):
    index = S3.index
    i_am_singular = S3.i_am_singular
    i_am_plural = S3.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(S3Auditor, self).__init__(accounts=accounts, debug=debug)
        self.policy_keys = ['Policy']

    def check_acl(self, s3_item):
        accounts = Account.query.all()
        S3_ACCOUNT_NAMES = [account.getCustom("s3_name").lower() for account in accounts if not account.third_party and account.getCustom("s3_name")]
        S3_CANONICAL_IDS = [account.getCustom("canonical_id").lower() for account in accounts if not account.third_party and account.getCustom("canonical_id")]
        S3_THIRD_PARTY_ACCOUNTS = [account.getCustom("s3_name").lower() for account in accounts if account.third_party and account.getCustom("s3_name")]
        S3_THIRD_PARTY_ACCOUNT_CANONICAL_IDS = [account.getCustom("canonical_id").lower() for account in accounts if account.third_party and account.getCustom("canonical_id")]

        # Get the owner ID:
        owner = s3_item.config["Owner"]["ID"].lower()

        acl = s3_item.config.get('Grants', {})
        for user in acl.keys():
            if user == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                message = "ACL - AuthenticatedUsers USED. "
                notes = "{}".format(",".join(acl[user]))
                self.add_issue(10, message, s3_item, notes=notes)
            elif user == 'http://acs.amazonaws.com/groups/global/AllUsers':
                message = "ACL - AllUsers USED."
                notes = "{}".format(",".join(acl[user]))
                self.add_issue(10, message, s3_item, notes=notes)
            elif user == 'http://acs.amazonaws.com/groups/s3/LogDelivery':
                message = "ACL - LogDelivery USED."
                notes = "{}".format(",".join(acl[user]))
                self.add_issue(0, message, s3_item, notes=notes)

            # DEPRECATED:
            elif user.lower() in S3_ACCOUNT_NAMES:
                message = "ACL - Friendly Account Access."
                notes = "{} {}".format(",".join(acl[user]), user)
                self.add_issue(0, message, s3_item, notes=notes)
            elif user.lower() in S3_THIRD_PARTY_ACCOUNTS:
                message = "ACL - Friendly Third Party Access."
                notes = "{} {}".format(",".join(acl[user]), user)
                self.add_issue(0, message, s3_item, notes=notes)

            elif user.lower() in S3_CANONICAL_IDS:
                # Owning account -- no issue
                if user.lower() == owner.lower():
                    continue

                message = "ACL - Friendly Account Access."
                notes = "{} {}".format(",".join(acl[user]), user)
                self.add_issue(0, message, s3_item, notes=notes)

            elif user.lower() in S3_THIRD_PARTY_ACCOUNT_CANONICAL_IDS:
                message = "ACL - Friendly Third Party Access."
                notes = "{} {}".format(",".join(acl[user]), user)
                self.add_issue(0, message, s3_item, notes=notes)

            else:
                message = "ACL - Unknown Cross Account Access."
                notes = "{} {}".format(",".join(acl[user]), user)
                self.add_issue(10, message, s3_item, notes=notes)

    def check_policy_exists(self, s3_item):
        policy = s3_item.config.get('Policy', {})
        if not policy:
            message = "POLICY - No Policy."
            self.add_issue(0, message, s3_item)
