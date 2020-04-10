# -*- coding: utf-8 -*-
# import module snippets
import sys
import io
import json
import objectpath
import Slack
import Box
import GSuite
import urllib.request
import logging
from urllib.parse import parse_qs
import lambda_tools
from lambda_tools import invoke
from lambda_tools import print_json
from lambda_tools import kms_decrypted
from lambda_tools import get_lambda_info
from lambda_tools import slack_verification


slack_token = kms_decrypted("SLACK_TOKEN")
slack_bot_token = kms_decrypted("SLACK_BOT_TOKEN")
slack_user = Slack.User(token=slack_bot_token)
slack_channel_ids = kms_decrypted("SLACK_CHANNEL_IDS", None)
if not (slack_channel_ids is None or slack_channel_ids == ""):
    slack_channel_ids = slack_channel_ids.split(",")

box_folder = None
box_file = None
gdrive = None
gdrive_permission = None
upload_type = kms_decrypted("UPLOAD_TYPE").lower()


def credential_setting():
    # Box用設定
    if "box" == upload_type:
        global box_file
        global box_folder
        logging.getLogger('boxsdk').setLevel(logging.CRITICAL)
        key_name = "/SlackUploadFileTransfer/Box"
        box_setting = lambda_tools.ssm_get_parameter(name=key_name)
        box_setting = json.loads(box_setting)
        settings = box_setting["boxAppSettings"]
        box_user = kms_decrypted("BOX_USER")
        box_folder = Box.Folder(
            client_id=settings["clientID"],
            client_secret=settings["clientSecret"],
            enterprise_id=box_setting["enterpriseID"],
            jwt_key_id=settings["appAuth"]["publicKeyID"],
            rsa_private_key_data=settings["appAuth"]["privateKey"]
        )
        box_folder.login(box_user)
        box_file = Box.File(
            client_id=settings["clientID"],
            client_secret=settings["clientSecret"],
            enterprise_id=box_setting["enterpriseID"],
            jwt_key_id=settings["appAuth"]["publicKeyID"],
            rsa_private_key_data=settings["appAuth"]["privateKey"]
        )
        box_file.login(box_user)
    # Google用設定
    if "google" == upload_type:
        global gdrive
        global gdrive_permission
        key_name = "/SlackUploadFileTransfer/GSuite"
        credential = lambda_tools.ssm_get_parameter(name=key_name)
        credential = json.loads(credential)
        gdrive = GSuite.Drive.Files(
            credential=credential,
            scopes=GSuite.Drive.SCOPES_MANAGE,
            delegate_user=credential["client_email"]
        )
        gdrive_permission = GSuite.Drive.Permissions(
            credential=credential,
            scopes=GSuite.Drive.SCOPES_MANAGE,
            delegate_user=credential["client_email"]
        )


def google_uploader(file, stream, length, event):
    name = file["name"]
    mime = file["mimetype"]
    buf = io.BytesIO(stream.read())
    # Google Drive用メタデータ作成
    metadata = GSuite.Drive.Metadata()
    metadata.name = name
    metadata.writersCanShare = True
    parent_id = kms_decrypted("GSUITE_PARENT_ID")
    metadata.parents = [parent_id]
    print_json({
        "type": "lambda",
        "message": "Slack上のFileをGoogle Driveにアップロードします",
        "name": name,
        "size": length
    })
    # Google Driveにアップロード
    file = gdrive.insert(
        metadata=metadata,
        file_stream=buf,
        original_mime_type=mime,
        fields='id, webViewLink, permissions'
    )
    print_json({
        "type": "lambda",
        "message": "Slack上のFileをGoogle Driveにアップロードしました",
        "name": name,
        "size": length
    })
    link = file.get("webViewLink")
    id = file.get("id")
    pids = file["permissions"]
    perm = {}
    perm["type"] = "domain"
    perm['role'] = 'reader'
    perm['domain'] = kms_decrypted("GSUITE_DOMAIN")
    gdrive_permission.create(file_id=id, permission=perm)
    link = file.get("webViewLink")
    return id, name, link


def box_create_user_folder(name: str):
    box_folder_id = kms_decrypted("BOX_FOLDER_ID")
    response = box_folder.items(folder_id=box_folder_id, fields=["name"])
    tree = objectpath.Tree(response)
    query = '$..entries[@.type is "folder" and @.name is "{}"].id'
    query = query.format(name)
    dt = list(tree.execute(query))
    if len(dt) > 0:
        return dt.pop()
    else:
        response = box_folder.create(name, box_folder_id, fields=["id"])
        return response["id"]


def box_uploader(file, stream, length, event):
    user_info = slack_user.info(event["user"])
    user_name = user_info["user"]["profile"]["display_name"]
    if user_name == "":
        user_name = user_info["user"]["name"]

    parent_id = box_create_user_folder(user_name)
    name = file["name"].split(".")
    base = name[0]
    ext = name[1]

    # Boxにアップロードが可能かPreFlightCheck
    name = "{}.{}".format(base, ext)
    try:
        box_file.preflight(name, parent_id, file["size"])
    except Exception as e:
        if e.code == "item_name_in_use":
            name = "{} ({}).{}".format(base, event["ts"], ext)
        else:
            raise e
    print_json({
        "type": "Box",
        "message": "Slack上のFileをBoxにアップロードします",
        "name": name,
        "size": length
    })
    # Upload
    try:
        if length <= 20000000:
            uploaded_file = box_file.upload(
                folder_id=parent_id, stream=io.BytesIO(stream.read()),
                name=name, overwrite=True
            )
        else:
            # Chunk upload
            session = box_file.client.folder(
                folder_id=parent_id
            ).create_upload_session(file_size=length, file_name=name)
            parts = []
            sha1 = hashlib.sha1()
            for part_index in range(session.total_parts):
                copied_length = 0
                chunk = b''
                while copied_length < session.part_size:
                    buffer = stream.read(session.part_size - copied_length)
                    if buffer is None:
                        continue
                    if len(buffer) == 0:
                        break
                    chunk += buffer
                    copied_length += len(buffer)
                    uploaded_part = session.upload_part_bytes(
                        chunk, part_index*session.part_size, length)
                    parts.append(uploaded_part)
                    updated_sha1 = sha1.update(chunk)
            content_sha1 = sha1.digest()
            uploaded_file = session.commit(
                content_sha1=content_sha1, parts=parts)
        link = uploaded_file.get_shared_link()
        print_json({
            "type": "Box",
            "message": "Slack上のFileをBoxにアップロードしました",
            "name": uploaded_file.name,
            "id": uploaded_file.id,
            "link": link
        })
        return uploaded_file.id, uploaded_file.name, link
    except Exception as e:
        raise e


def downloader(file):
    headers = {"Authorization": "Bearer {}".format(slack_token)}
    dl_url = file.get("url_private_download", None)
    if dl_url is None:
        path = "https://slack.com/api/files.info"
        url = "{}?{}".format(
            path, urllib.parse.urlencode({"file": file["id"]}))
        args = {"url": url, "headers": headers}
        req = urllib.request.Request(**args)
        try:
            res = urllib.request.urlopen(req)
            body = json.loads(res.read().decode('utf-8'))
            dl_url = body["file"]["url_private_download"]
        except Exception as e:
            raise e
    try:
        args = {"url": dl_url, "headers": headers}
        req = urllib.request.Request(**args)
        res = urllib.request.urlopen(req)
        return res, file.get('size')
    except Exception as e:
        raise e


def transfer(file, event):
    stream, length = downloader(file)
    func = "{}_uploader".format(upload_type)
    return eval(func)(file, stream, length, event)


def main_function(data, context):
    credential_setting()
    body = data.get("body", {})
    event = body.get("event", {})
    text = event.get("text", None)
    channel_id = event.get("channel", None)
    channel_type = event.get("channel_type", None)
    ts = event.get("ts", None)
    files = event.get("files", [])
    user_id = event.get("user")
    thread_ts = event.get("thread_ts", None)
    blocks = event.get("blocks", None)

    links = []
    for file in files:
        try:
            id, name, link = transfer(file, event)
            links.append(link)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print_json({
                    "level": "warning",
                    "type": "Slack",
                    "message": "Slack上にFileが存在しません",
                    "id": file["id"],
                    "name": file["name"]
                })
                continue
            raise e
        except Exception as e:
            raise e
    if len(links) == 0:
        return
    # Slack処理
    user_info = slack_user.info(user_id)
    profile = user_info["user"]["profile"]
    user_icon = profile.get("image_original", profile["image_192"])
    user_name = profile.get("display_name")
    if user_name == "":
        user_name = profile.get("real_name")
    if channel_type == "im":
        channel_id = user_id
    try:
        slack_chat = Slack.Chat(token=slack_bot_token)
        message = {
            "channel": channel_id,
            "text": "{}\n{}".format(text, "\n".join(links)),
            "link_names": True,
            "username": user_name,
            "icon_url": user_icon,
            "thread_ts": thread_ts
        }
        print_json({
            "type": "Slack",
            "message": "Slack上にメッセージをPostします",
            "data": message
        })
        slack_chat.post_message(**message)
    except Exception as e:
        raise e
    # 古いメッセージを削除
    try:
        print_json({
            "type": "Slack",
            "message": "Slack上の古いメッセージを削除します",
            "channel": channel_id,
            "ts": ts
        })
        slack_chat = Slack.Chat(token=slack_token)
        slack_chat.delete(channel=channel_id, ts=ts, as_user=True)
    except Exception as e:
        print_json({
            "type": "Slac",
            "level": "error",
            "request-id": lambda_tools.aws_request_id,
            "channel": channel_id,
            "ts": ts,
            "message": "メッセージ削除に失敗しました[{}]".format(str(e))
        })
    # Slack上のファイルを削除
    slack_file = Slack.File(token=slack_token)
    for file in files:
        try:
            print_json({
                "type": "Slack",
                "message": "Slack上のファイルを削除します",
                "file": file["id"],
                "name": file["name"]
            })
            slack_file.delete(file=file["id"])
        except Exception as e:
            print_json({
                "type": "lambda",
                "level": "error",
                "request-id": lambda_tools.aws_request_id,
                "message": "ファイル削除に失敗しました[{}]".format(str(e)),
                "file": file["id"],
                "name": file["name"]
            })


def lambda_handler(event, context):
    get_lambda_info(context, "SlackUploadFileTransfer-Receiver")
    print_json({
        "type": "lambda", "message": "イベント受信",
        "payload": event
    })
    if "X-Slack-Retry-Reason" in event["headers"]:
        if event["headers"]["X-Slack-Retry-Reason"] == "http_timeout":
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "OK"
            }
    try:
        if isinstance(event["body"], str):
            slack_verification(event)
            event["body"] = json.loads(event["body"])
            if "challenge" in event["body"]:
                print_json({
                    "type": "lambda", "message": "チャレンジイベント受信",
                    "payload": event
                })
                return {
                    'statusCode': '200',
                    'body': event["body"]["challenge"]
                }
            subtype = event["body"]["event"].get("subtype", None)
            channel = event["body"]["event"].get("channel", None)
            if slack_channel_ids is not None:
                if channel not in slack_channel_ids:
                    return {
                        "statusCode": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": "OK"
                    }
            if subtype == "file_share":
                print_json({
                    "type": "lambda", "message": "FileShareイベント受信",
                    "payload": event
                })
                print_json({
                    "type": "lambda",
                    "message": "Lambdaを再帰呼出しします"
                })
                if lambda_tools.aws_request_id == "debug":
                    return lambda_handler(event, context)
                else:
                    invoke(event)
        else:
            main_function(event, context)
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": "OK"
        }
    except Exception as e:
        print_json({
            "type": "lambda",
            "level": "error",
            "request-id": lambda_tools.aws_request_id,
            "message": str(e),
            "event": event,
            "reason": lambda_tools.exception_fail(e)
        })
        return {
            "statusCode": 502,
            "headers": {},
            "body": json.dumps({
                "text": str(e)
            })
        }
