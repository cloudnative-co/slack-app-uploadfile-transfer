# -*- coding: utf-8 -*-
import json
import boto3
import botocore
import base64
import re
import os
import sys
import traceback
import time
import hmac
import hashlib

aws_request_id = None
function_name = None
region = os.environ.get("REGION", "ap-northeast-1")

kms = boto3.client('kms', region_name=region)
ssm = boto3.client('ssm', region_name=region)
lambda_client = boto3.client('lambda', region_name=region)


def exception_fail(e):
    info = sys.exc_info()
    tbinfo = traceback.format_tb(info[2])
    exception_name = str(info[1])
    result = {}
    result["msg"] = exception_name
    result["trace"] = []
    for info in tbinfo:
        message = info.split("\n")
        temp = message[0].split(", ")
        del message[0]
        places = {
            "file": temp[0].replace("  File", ""),
            "line": temp[1].replace("line ", ""),
            "func": temp[2].replace("in ", ""),
            "trac": message
        }
        result["trace"].append(places)
    return result



def get_lambda_info(context, funcname_default):
    global function_name
    global aws_request_id
    if context is not None:
        if context.function_name == "test":
            aws_request_id = "debug"
            function_name = os.environ.get("FUNCTION_NAME", funcname_default)
        else:
            aws_request_id = context.aws_request_id
            function_name = context.function_name
    else:
        aws_request_id = "debug"
        function_name = os.environ.get("FUNCTION_NAME", funcname_default)


def print_json(message):
    if isinstance(message, str) or isinstance(message, list):
        message = {
            "level": "info",
            "message": message
        }
    if isinstance(message, dict):
        if "level" not in message:
            message["level"] = "info"

    message["request-id"] = aws_request_id
    if aws_request_id == "debug":
        print(json.dumps(message, ensure_ascii=False, indent=4))
    else:
        if message["level"] == "debug":
            return
        print(json.dumps(message, ensure_ascii=False))


def ssm_get_parameter(name: str):
    def decrypt(encrypted):
        try:
            blob = base64.b64decode(encrypted)
            decrypted = kms.decrypt(CiphertextBlob=blob)['Plaintext']
            return decrypted.decode('utf-8')
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "InvalidCiphertextException":
                return encrypted
            raise e
        except base64.binascii.Error as e:
            return encrypted
        except ValueError as e:
            return encrypted
        except Exception as e:
            return default
    data = ssm.get_parameter(Name=name)
    return decrypt(data["Parameter"]["Value"])


def kms_decrypted(key, default=None):
    if key not in os.environ:
        return default
    ENCRYPTED = os.environ[key]
    if ENCRYPTED is None:
        return default
    if ENCRYPTED == "":
        return default
    try:
        blob = base64.b64decode(ENCRYPTED)
        DECRYPTED = kms.decrypt(CiphertextBlob=blob)['Plaintext']
        return DECRYPTED.decode('utf-8')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "InvalidCiphertextException":
            return ENCRYPTED
        raise e
    except base64.binascii.Error as e:
        return ENCRYPTED
    except ValueError as e:
        return ENCRYPTED
    except Exception as e:
        return default


def invoke(payload: dict):
    """
    @brief      Lambdaの再帰処理
    """
    global function_name
    try:
        lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps(payload)
        )
    except Exception as e:
        raise e


def zoom_verification(event: dict):
    if "headers" not in event:
        raise Exception("header not found")
    if "Authorization" not in event["headers"]:
        raise Exception("Authorization header not found")

    authoriztion = event["headers"]["Authorization"]
    token = kms_decrypted("ZOOM_VERIFICATION_TOKEN")
    if authoriztion != token:
        raise Exception("Verification token was not match")


def slack_verification(event: dict):
    secretkey = kms_decrypted("SLACK_SIGNING_SECRET", None)

    if not secretkey:
        return Exception("Signing Secret not found")
    if "X-Slack-Request-Timestamp" not in event["headers"] \
        or "X-Slack-Signature" not in event["headers"]:
        raise Exception("Header Invalid")


    timestamp = event["headers"]["X-Slack-Request-Timestamp"]
    signature = event["headers"]["X-Slack-Signature"]

    if abs(time.time() - int(timestamp)) > 60 * 5:
        if aws_request_id != "debug":
            raise Exception("Timestamp Invalid")

    body = event["body"]
    message = "v0:{}:{}".format(timestamp, body)
    message_bytes = bytes(message, 'UTF-8')
    request_hash = 'v0=' + hmac.new(
        str.encode(secretkey),
        message_bytes,
        hashlib.sha256
    ).hexdigest()

    result = False
    if hasattr(hmac, "compare_digest"):
        if (sys.version_info[0] == 2):
            result = hmac.compare_digest(bytes(request_hash), bytes(signature))
        else:
            result = hmac.compare_digest(request_hash, signature)
    else:
        if len(request_hash) != len(signature):
            raise Exception("Signature invalid")
        result = 0
        if isinstance(request_hash, bytes) and isinstance(signature, bytes):
            for x, y in zip(request_hash, signature):
                result |= x ^ y
        else:
            for x, y in zip(request_hash, signature):
                result |= ord(x) ^ ord(y)
        result = result == 0

    if not result:
        raise Exception("Signature invalid")
    return result
