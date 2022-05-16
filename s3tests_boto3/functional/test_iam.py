import json
from operator import eq

from botocore.exceptions import ClientError
from nose.plugins.attrib import attr

from s3tests.functional.utils import assert_raises
from . import get_tenant_iam_client, get_tenant_user_id
from .utils import _get_status


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_invalid_user():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy using parameter value outside limit')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_parameter_limit():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}] * 1000
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy' * 10, UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 400)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy using invalid policy document elements')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_invalid_element():
    client = get_tenant_iam_client()

    # With Version other than 2012-10-17
    policy_document = json.dumps(
        {"Version": "2010-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 400)

    # With no Statement
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
        }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 400)

    # with same Sid for 2 statements
    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [
             {"Sid": "98AB54CF",
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"},
             {"Sid": "98AB54CF",
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 400)

    # with Principal
    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*",
             "Principal": "arn:aws:iam:::username"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 400)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put a policy that already exists')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_existing_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}
         }
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify List User policies')
@attr(assertion='succeeds')
@attr('user-policy')
def test_list_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}
         }
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    response = client.list_user_policies(UserName=get_tenant_user_id())
    eq("AllAccessPolicy" in response["PolicyNames"], True)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify List User policies with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_list_user_policy_invalid_user():
    client = get_tenant_iam_client()
    e = assert_raises(ClientError, client.list_user_policies, UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)
