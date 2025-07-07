import json
import re
import traceback
import requests
import time
from typing import Mapping, List, Tuple
from werkzeug import Request, Response
from dify_plugin import Endpoint
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# ref: https://github.com/fla9ua/markdown_to_mrkdwn
class SlackMarkdownConverter:
    """
    A converter class to transform Markdown text into Slack's mrkdwn format.

    Attributes:
        encoding (str): The character encoding used for the conversion.
        patterns (List[Tuple[str, str]]): A list of regex patterns and their replacements.
    """

    def __init__(self, encoding="utf-8"):
        """
        Initializes the SlackMarkdownConverter with a specified encoding.

        Args:
            encoding (str): The character encoding to use for the conversion. Default is 'utf-8'.
        """
        self.encoding = encoding
        self.in_code_block = False
        self.table_replacements = {}
        # Use compiled regex patterns for better performance
        self.patterns: List[Tuple[re.Pattern, str]] = [
            (
                re.compile(r"^(\s*)- \[([ ])\] (.+)", re.MULTILINE),
                r"\1• ☐ \3",
            ),  # Unchecked task list
            (
                re.compile(r"^(\s*)- \[([xX])\] (.+)", re.MULTILINE),
                r"\1• ☑ \3",
            ),  # Checked task list
            (re.compile(r"^(\s*)- (.+)", re.MULTILINE), r"\1• \2"),  # Unordered list
            (
                re.compile(r"^(\s*)(\d+)\. (.+)", re.MULTILINE),
                r"\1\2. \3",
            ),  # Ordered list
            (re.compile(r"!\[.*?\]\((.+?)\)", re.MULTILINE), r"<\1>"),  # Images to URL
            (
                re.compile(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", re.MULTILINE),
                r"_\1_",
            ),  # Italic
            (re.compile(r"^###### (.+)$", re.MULTILINE), r"*\1*"),  # H6 as bold
            (re.compile(r"^##### (.+)$", re.MULTILINE), r"*\1*"),  # H5 as bold
            (re.compile(r"^#### (.+)$", re.MULTILINE), r"*\1*"),  # H4 as bold
            (re.compile(r"^### (.+)$", re.MULTILINE), r"*\1*"),  # H3 as bold
            (re.compile(r"^## (.+)$", re.MULTILINE), r"*\1*"),  # H2 as bold
            (re.compile(r"^# (.+)$", re.MULTILINE), r"*\1*"),  # H1 as bold
            (
                re.compile(r"(^|\s)~\*\*(.+?)\*\*(\s|$)", re.MULTILINE),
                r"\1 *\2* \3",
            ),  # Bold with space handling
            (re.compile(r"(?<!\*)\*\*(.+?)\*\*(?!\*)", re.MULTILINE), r"*\1*"),  # Bold
            (re.compile(r"__(.+?)__", re.MULTILINE), r"*\1*"),  # Underline as bold
            (re.compile(r"\[(.+?)\]\((.+?)\)", re.MULTILINE), r"<\2|\1>"),  # Links
            (re.compile(r"`(.+?)`", re.MULTILINE), r"`\1`"),  # Inline code
            (re.compile(r"^> (.+)", re.MULTILINE), r"> \1"),  # Blockquote
            (
                re.compile(r"^(---|\*\*\*|___)$", re.MULTILINE),
                r"──────────",
            ),  # Horizontal line
            (re.compile(r"~~(.+?)~~", re.MULTILINE), r"~\1~"),  # Strikethrough
        ]
        # Placeholders for triple emphasis
        self.triple_start = "%%BOLDITALIC_START%%"
        self.triple_end = "%%BOLDITALIC_END%%"

    def convert(self, markdown: str) -> str:
        """
        Convert Markdown text to Slack's mrkdwn format.

        Args:
            markdown (str): The Markdown text to convert.

        Returns:
            str: The converted text in Slack's mrkdwn format.
        """
        if not markdown:
            return ""

        try:
            markdown = markdown.strip()

            self.table_replacements = {}

            markdown = self._convert_tables(markdown)

            lines = markdown.split("\n")
            converted_lines = [self._convert_line(line) for line in lines]
            result = "\n".join(converted_lines)

            for placeholder, table in self.table_replacements.items():
                result = result.replace(placeholder, table)

            return result.encode(self.encoding).decode(self.encoding)
        except Exception as e:
            # Log the error for debugging
            return markdown

    def _convert_tables(self, markdown: str) -> str:
        """
        Convert Markdown tables to Slack's mrkdwn format.

        Args:
            markdown (str): The Markdown text containing tables.

        Returns:
            str: The text with tables converted to Slack's format.
        """
        table_pattern = re.compile(
            r"^\|(.+)\|\s*$\n^\|[-:| ]+\|\s*$(\n^\|.+\|\s*$)*", re.MULTILINE
        )

        def convert_table(match):
            original_table = match.group(0)

            table_lines = original_table.strip().split("\n")
            header_line = table_lines[0]
            separator_line = table_lines[1]
            data_lines = table_lines[2:] if len(table_lines) > 2 else []

            headers = [cell.strip() for cell in header_line.strip("|").split("|")]

            rows = []
            for line in data_lines:
                cells = [cell.strip() for cell in line.strip("|").split("|")]
                rows.append(cells)

            result = []
            result.append(" | ".join(f"*{header}*" for header in headers))

            for row in rows:
                result.append(" | ".join(row))

            placeholder = f"%%TABLE_PLACEHOLDER_{hash(original_table)}%%"
            self.table_replacements[placeholder] = "\n".join(result)
            return placeholder

        return table_pattern.sub(convert_table, markdown)

    def _convert_line(self, line: str) -> str:
        """
        Convert a single line of Markdown.

        Args:
            line (str): A single line of Markdown text.

        Returns:
            str: The converted line in Slack's mrkdwn format.
        """
        if line.startswith("%%TABLE_PLACEHOLDER_") and line.endswith("%%"):
            return line

        code_block_match = re.match(r"^```(\w*)$", line)
        if code_block_match:
            language = code_block_match.group(1)
            self.in_code_block = not self.in_code_block
            if self.in_code_block and language:
                return f"```{language}"
            return "```"

        if self.in_code_block:
            return line

        line = re.sub(
            r"(?<!\*)\*\*\*([^*\n]+?)\*\*\*(?!\*)",
            lambda m: f"{self.triple_start}{m.group(1)}{self.triple_end}",
            line,
        )

        for pattern, replacement in self.patterns:
            line = pattern.sub(replacement, line)

        line = re.sub(
            re.escape(self.triple_start) + r"(.*?)" + re.escape(self.triple_end),
            r"*_\1_*",
            line,
            flags=re.MULTILINE,
        )

        return line.rstrip()


class SlackEndpoint(Endpoint):
    CACHE_PREFIX = "thread-cache"
    CACHE_DURATION = 60 * 60 * 24  # 24 hour
    CLEANUP_INTERVAL = 60 * 60 * 24  # 24 hours

    def _add_key_to_registry(self, key: str):
        """キーをレジストリに追加"""
        if key == "__keys__":  # 無限ループ防止
            return
        
        try:
            # 現在のレジストリを取得
            registry = self._get_key_registry()
            
            # キーを追加（既存の場合は時間を更新）
            registry[key] = int(time.time())  # last_update時刻
            registry["__last_updated"] = int(time.time())
            
            # レジストリを保存
            self.session.storage.set("__keys__", json.dumps(registry).encode("utf-8"))
            
        except Exception as e:
            print(f"Error adding key to registry: {e}")

    def _remove_key_from_registry(self, key: str):
        """キーをレジストリから削除"""
        if key == "__keys__":
            return
        
        try:
            registry = self._get_key_registry()
            
            if key in registry:
                del registry[key]
                registry["__last_updated"] = int(time.time())
                self.session.storage.set("__keys__", json.dumps(registry).encode("utf-8"))
                
        except Exception as e:
            print(f"Error removing key from registry: {e}")

    def _get_key_registry(self) -> dict:
        """キーレジストリを取得"""
        try:
            raw = self.session.storage.get("__keys__")
            if raw:
                return json.loads(raw.decode("utf-8"))
            else:
                return {"__last_updated": int(time.time())}
        except Exception:
            return {"__last_updated": int(time.time())}

    def _get_all_keys(self) -> List[str]:
        """全てのキーを取得（__last_updated以外）"""
        try:
            registry = self._get_key_registry()
            return [k for k in registry.keys() if k != "__last_updated"]
        except Exception:
            return []

    def _cleanup_storage(self, cleanup_percentage: float = 0.5):
        """storageをクリーンアップ（古いキーから削除）"""
        try:
            registry = self._get_key_registry()
            
            # __last_updated以外のキーを取得
            keys_with_time = [(k, v) for k, v in registry.items() if k != "__last_updated"]
            
            if not keys_with_time:
                return
            
            # 時刻で昇順ソート（古いものから）
            keys_with_time.sort(key=lambda x: x[1])
            
            # 削除するキーの数を計算
            total_keys = len(keys_with_time)
            keys_to_delete = int(total_keys * cleanup_percentage)
            
            if keys_to_delete > 0:
                # 古いキーから削除
                for i in range(keys_to_delete):
                    key_to_delete = keys_with_time[i][0]
                    try:
                        self.session.storage.delete(key_to_delete)
                        self._remove_key_from_registry(key_to_delete)
                    except Exception as e:
                        print(f"Error deleting key {key_to_delete}: {e}")
                
                print(f"Storage cleanup completed: deleted {keys_to_delete} keys out of {total_keys}")
            
        except Exception as e:
            print(f"Error during storage cleanup: {e}")

    def _should_cleanup_storage(self) -> bool:
        """24時間間隔でストレージクリーンアップが必要かチェック"""
        try:
            registry = self._get_key_registry()
            last_cleanup = registry.get("__last_cleanup", 0)
            current_time = int(time.time())
            return (current_time - last_cleanup) >= self.CLEANUP_INTERVAL
        except Exception:
            return False

    def _periodic_cleanup_if_needed(self):
        """必要に応じて定期クリーンアップを実行（30%削除）"""
        if self._should_cleanup_storage():
            try:
                # 軽めのクリーンアップ（30%削除）
                self._cleanup_storage(cleanup_percentage=0.3)
                
                # クリーンアップ時刻を記録
                registry = self._get_key_registry()
                registry["__last_cleanup"] = int(time.time())
                self.session.storage.set("__keys__", json.dumps(registry).encode("utf-8"))
                
                print("Periodic storage cleanup completed")
            except Exception as e:
                print(f"Error during periodic cleanup: {e}")

    def _load_cached_history(self, channel: str, thread_ts: str):
        key = f"{self.CACHE_PREFIX}-{channel}-{thread_ts}"
        try:
            raw = self.session.storage.get(key)
            if raw:
                data = json.loads(raw.decode("utf-8"))
            else:
                return []
        except Exception:
            return []

        now = time.time()
        messages = [m for m in data.get("messages", []) if now - m.get("saved_at", now) < self.CACHE_DURATION]
        if len(messages) != len(data.get("messages", [])):
            data["messages"] = messages
            data["last_cleanup"] = now
            try:
                self._add_key_to_registry(key)
                self.session.storage.set(key, json.dumps(data).encode("utf-8"))
            except Exception:
                pass
        return messages

    def _append_thread_message(self, channel: str, thread_ts: str, message: Mapping):
        key = f"{self.CACHE_PREFIX}-{channel}-{thread_ts}"
        now = time.time()
        try:
            raw = self.session.storage.get(key)
            if raw:
                data = json.loads(raw.decode("utf-8"))
            else:
                data = {"messages": [], "last_cleanup": now}
        except Exception:
            data = {"messages": [], "last_cleanup": now}

        data["messages"] = [m for m in data.get("messages", []) if now - m.get("saved_at", now) < self.CACHE_DURATION]
        msg = dict(message)
        msg["saved_at"] = now
        data["messages"].append(msg)
        data["last_cleanup"] = now
        try:
            self._add_key_to_registry(key)
            self.session.storage.set(key, json.dumps(data).encode("utf-8"))
        except Exception:
            pass

    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        """
        Invokes the endpoint with the given request.
        """
        # 定期クリーンアップチェック
        self._periodic_cleanup_if_needed()
        
        # Check if this is a retry and if we should ignore it
        retry_num = r.headers.get("X-Slack-Retry-Num")
        if not settings.get("allow_retry") and (
            r.headers.get("X-Slack-Retry-Reason") == "http_timeout"
            or ((retry_num is not None and int(retry_num) > 0))
        ):
            return Response(status=200, response="ok")

        # Parse the incoming JSON data
        data = r.get_json()

        # Handle Slack URL verification challenge
        if data.get("type") == "url_verification":
            return Response(
                response=json.dumps({"challenge": data.get("challenge")}),
                status=200,
                content_type="application/json",
            )

        # Handle Slack events
        if data.get("type") == "event_callback":
            event = data.get("event")

            # allowed_channel設定を取得
            allowed_channel_setting = settings.get("allowed_channel", "").strip()

            # Handle different event types
            if event.get("type") == "app_mention":
                # Handle mention events - when the bot is @mentioned
                message = event.get("text", "")

                # Remove the bot mention from the beginning of the message
                message = re.sub(r"^<@[^>]+>\s*", "", message)

                # Get channel ID and thread timestamp
                channel = event.get("channel", "")
                # Use thread_ts if the message is in a thread, or use ts to start a new thread
                thread_ts = event.get("thread_ts", event.get("ts"))

                # Process the message and respond
                token = settings.get("bot_token")
                client = WebClient(token=token)

                # Check if this is a cache deletion request
                if message.strip().lower() == "delcache":
                    # Delete thread cache
                    cache_key = f"{self.CACHE_PREFIX}-{channel}-{thread_ts}"
                    conversation_key = f"slack-{channel}-{thread_ts}"
                    
                    try:
                        # Delete both cache and conversation storage
                        self._remove_key_from_registry(cache_key)
                        self.session.storage.delete(cache_key)
                        self._remove_key_from_registry(conversation_key)
                        self.session.storage.delete(conversation_key)
                        
                        # Send confirmation message
                        client.chat_postMessage(
                            channel=channel,
                            thread_ts=thread_ts,
                            text=f"✅ Thread cache has been successfully deleted. \n{cache_key} \n{conversation_key}"
                        )
                    except Exception as e:
                        print(f"Error deleting cache: {e}")
                        # Send error message
                        try:
                            client.chat_postMessage(
                                channel=channel,
                                thread_ts=thread_ts,
                                text=f"❌ Error deleting cache: {str(e)}"
                            )
                        except SlackApiError:
                            pass
                    
                    return Response(
                        status=200, response="ok", content_type="text/plain"
                    )

                # store the incoming app mention message
                self._append_thread_message(
                    channel,
                    thread_ts,
                    {
                        "ts": event.get("ts"),
                        "text": event.get("text", ""),
                        "user": event.get("user"),
                        "bot_id": event.get("bot_id"),
                    },
                )

                # allowed_channel が指定されているかチェック
                if allowed_channel_setting:
                    try:
                        # チャンネルIDからチャンネル名を取得
                        channel_info = client.conversations_info(channel=channel)
                        actual_channel_name = channel_info["channel"]["name"]
                        # 取得したチャンネル名に "#" を付けて比較
                        current_channel_with_hash = f"#{actual_channel_name}"
                        if current_channel_with_hash != allowed_channel_setting:
                            # 許可されたチャンネルではなかった場合、メッセージを返して終了
                            client.chat_postMessage(
                                channel=channel,
                                thread_ts=thread_ts,
                                text=(
                                    f"Current channel: {current_channel_with_hash} is not allowed."
                                ),
                            )
                            return Response(
                                status=200, response="ok", content_type="text/plain"
                            )
                    except SlackApiError as e:
                        print(f"Error getting channel info: {e}")
                        try:
                            client.chat_postMessage(
                                channel=channel,
                                thread_ts=thread_ts,
                                text=(
                                    f"Failed to retrieve channel info. SlackApiError: {str(e)}"
                                ),
                            )
                        except SlackApiError:
                            pass
                        return Response(
                            status=200, response="ok", content_type="text/plain"
                        )
                    except Exception as e:
                        print(f"Unexpected error: {e}")
                        try:
                            client.chat_postMessage(
                                channel=channel,
                                thread_ts=thread_ts,
                                text=(
                                    f"An unexpected error occurred while retrieving channel info. Error: {str(e)}"
                                ),
                            )
                        except SlackApiError:
                            pass
                        return Response(
                            status=200, response="ok", content_type="text/plain"
                        )

                try:
                    # Create a key to check if the conversation already exists
                    key_to_check = f"slack-{channel}-{thread_ts}"
                    conversation_id = None
                    try:
                        conversation_id = self.session.storage.get(key_to_check)
                    except Exception as e:
                        err = traceback.format_exc()

                    # Get thread history for better context
                    thread_history = []
                    user_id_list = []
                    if thread_ts:
                        messages = self._load_cached_history(channel, thread_ts)
                        if not messages:
                            try:
                                replies = client.conversations_replies(
                                    channel=channel, ts=thread_ts
                                )
                                messages = replies.get("messages", [])
                            except SlackApiError as e:
                                if e.response.get("error") == "ratelimited":
                                    # Get retry-after header from Slack's response
                                    retry_after = int(e.response.get("headers", {}).get("Retry-After", 60))
                                    try:
                                        client.chat_postMessage(
                                            channel=channel,
                                            thread_ts=thread_ts,
                                            text=f"Rate limit reached when retrieving thread. Retrying in {retry_after} seconds...",
                                        )
                                    except SlackApiError:
                                        pass
                                    time.sleep(retry_after)
                                    try:
                                        replies = client.conversations_replies(
                                            channel=channel, ts=thread_ts
                                        )
                                        messages = replies.get("messages", [])
                                    except SlackApiError as e:
                                        print(
                                            f"Error getting thread history after retry: {e}"
                                        )
                                        messages = []
                                else:
                                    print(f"Error getting thread history: {e}")
                                    messages = []

                            for m in messages:
                                self._append_thread_message(channel, thread_ts, m)

                        # user list in the thread
                        # pattern to extract user id from slack message
                        pattern = r"<@([^>]+)>"
                        # Format messages for context
                        for msg in messages:
                                role = "assistant" if msg.get("bot_id") else "user"
                                content = msg.get("text", "")
                                thread_history.append(
                                    {
                                        "role": role,
                                        "participant_id": msg.get("user", "unknown"),
                                        "content": content,
                                    }
                                )
                                user_id = msg.get("user", "unknown")
                                if user_id != "unknown" and user_id not in user_id_list:
                                    user_id_list.append(user_id)
                                if content != "":
                                    user_ids = re.findall(pattern, content)
                                    for user_id in user_ids:
                                        if user_id not in user_id_list:
                                            user_id_list.append(user_id)


                        # get user display name map from user id list
                        user_display_name_map = {}
                        try:
                            for user_id in user_id_list:
                                user_info = client.users_info(user=user_id)
                                user_display_name = user_info.get("user", {}).get(
                                    "name", ""
                                )
                                user_real_name = user_info.get("user", {}).get(
                                    "real_name", ""
                                )
                                if user_display_name != "":
                                    user_display_name_map[user_id] = (
                                        user_real_name + " (" + user_display_name + ")"
                                    )
                                else:
                                    user_display_name_map[user_id] = user_real_name
                        except SlackApiError as e:
                            print(f"Error getting user info: {e}")

                        # add user display name to thread history
                        pattern = r"<@([A-Za-z0-9]+)>"

                        def replace_id_with_name(match):
                            user_id = match.group(1)  # <@...>の...部分を取り出す
                            # user_display_name_mapに存在する場合のみ置換
                            if user_id in user_display_name_map:
                                return f"@{user_display_name_map[user_id]}"
                            else:
                                # 不明なIDの場合はそのままにしておく
                                return match.group(0)

                        for msg in thread_history:
                            msg["participant_name"] = user_display_name_map.get(
                                msg.get("participant_id", "unknown"), "unknown"
                            )
                            msg["content"] = re.sub(
                                pattern, replace_id_with_name, msg["content"]
                            )

                    uploaded_files = []
                    slack_files = event.get("files", [])
                    if slack_files:
                        for f in slack_files:
                            file_name = f.get("name")
                            file_url = f.get("url_private_download")
                            file_mimetype = f.get(
                                "mimetype", "application/octet-stream"
                            )
                            if not file_url or not file_name:
                                continue

                            headers = {"Authorization": f"Bearer {token}"}
                            resp = requests.get(file_url, headers=headers)
                            if resp.status_code == 200:
                                try:
                                    storage_file = self.session.file.upload(
                                        filename=file_name,
                                        content=resp.content,
                                        mimetype=file_mimetype,
                                    )
                                    if storage_file:
                                        uploaded_files.append(storage_file)
                                except Exception as e:
                                    try:
                                        client.chat_postMessage(
                                            channel=channel,
                                            thread_ts=thread_ts,
                                            text=(
                                                f"Error uploading file: {e}\n\n"
                                                "This may be caused by an unconfigured `FILES_URL` in your `dify/docker/.env` .\n"
                                                "Please set `FILES_URL` properly and restart( `docker compose down && docker compose up -d` ) your Dify environment, then try again."
                                            ),
                                        )
                                    except SlackApiError:
                                        pass
                                    print(
                                        f"Error uploading file via session.file.upload: {e}"
                                    )
                            else:
                                print(
                                    f"Failed to download file from Slack: {file_name}, status code={resp.status_code}"
                                )

                    # Invoke the Dify app with the message
                    app_invoke_inputs = {
                        "thread_history": json.dumps(
                            thread_history, indent=4, ensure_ascii=False
                        ),
                        "thread_users": json.dumps(
                            user_display_name_map, indent=4, ensure_ascii=False
                        ),
                        "thread_ts": thread_ts,
                        "channel_id": channel,
                    }
                    if uploaded_files:
                        app_invoke_inputs["files"] = [
                            {
                                "type": uf.type,
                                "transfer_method": "remote_url",
                                "url": uf.preview_url,
                            }
                            for uf in uploaded_files
                        ]

                    invoke_params = {
                        "app_id": settings["app"]["app_id"],
                        "query": re.sub(pattern, replace_id_with_name, message),
                        "inputs": app_invoke_inputs,
                        "response_mode": "blocking",
                    }
                    if conversation_id is not None:
                        invoke_params["conversation_id"] = conversation_id.decode(
                            "utf-8"
                        )

                    response = self.session.app.chat.invoke(**invoke_params)
                    answer = response.get("answer")
                    conversation_id = response.get("conversation_id")
                    if conversation_id:
                        self._add_key_to_registry(key_to_check)
                        self.session.storage.set(
                            key_to_check, conversation_id.encode("utf-8")
                        )

                    try:
                        converter = SlackMarkdownConverter()
                        converted_answer = converter.convert(answer)

                        # Slackで指定されている3,000文字以上の場合は分割
                        # https://api.slack.com/reference/block-kit/composition-objects#text__fields
                        MAX_MSG_LEN = 3000
                        if len(converted_answer) > MAX_MSG_LEN:
                            lines = converted_answer.split("\n")
                            chunks = []
                            current_chunk = ""

                            for line in lines:
                                # line自体がMAX_MSG_LENを超える場合を考慮
                                if len(line) > MAX_MSG_LEN:
                                    # lineをさらにサブ分割
                                    sub_chunks = [
                                        line[i : i + MAX_MSG_LEN]
                                        for i in range(0, len(line), MAX_MSG_LEN)
                                    ]
                                    for sub in sub_chunks:
                                        # current_chunk に積み上げられるなら積む
                                        if (
                                            len(current_chunk)
                                            + (len(sub) + (1 if current_chunk else 0))
                                            <= MAX_MSG_LEN
                                        ):
                                            if current_chunk:
                                                current_chunk += "\n"
                                            current_chunk += sub
                                        else:
                                            # 今のチャンクを確定させて次へ
                                            chunks.append(current_chunk)
                                            current_chunk = sub
                                else:
                                    # lineがMAX_MSG_LEN以内なら従来の行ごと処理
                                    added_length = len(line) + (
                                        1 if current_chunk else 0
                                    )
                                    if len(current_chunk) + added_length <= MAX_MSG_LEN:
                                        if current_chunk:
                                            current_chunk += "\n"
                                        current_chunk += line
                                    else:
                                        chunks.append(current_chunk)
                                        current_chunk = line

                            # 最後に残っていたら追加
                            if current_chunk:
                                chunks.append(current_chunk)
                        else:
                            chunks = [converted_answer]

                        # ブロードキャストするかどうか
                        reply_broadcast = (
                            settings.get("first_reply_broadcast", False)
                            and len(thread_history) == 1
                        )

                        for i, chunk in enumerate(chunks):
                            # 分割したチャンクを blocks に載せる
                            answer_blocks = [
                                {
                                    "type": "section",
                                    "text": {"type": "mrkdwn", "text": chunk},
                                }
                            ]
                            # 2つ目以降のメッセージでブロードキャストされるとスレッド外にも大量に通知されてしまうので、
                            # 必要に応じて一度目のみブロードキャストにする
                            chunk_reply_broadcast = reply_broadcast if i == 0 else False

                            resp = client.chat_postMessage(
                                channel=channel,
                                text=chunk,  # fallback用テキスト
                                thread_ts=thread_ts,
                                blocks=answer_blocks,
                                reply_broadcast=chunk_reply_broadcast,
                            )
                            self._append_thread_message(
                                channel,
                                thread_ts,
                                {
                                    "ts": resp.get("ts"),
                                    "text": chunk,
                                    "user": resp.get("message", {}).get("user"),
                                    "bot_id": resp.get("message", {}).get("bot_id"),
                                },
                            )

                        return Response(
                            status=200, response="ok", content_type="text/plain"
                        )

                    except SlackApiError as e:
                        return Response(
                            status=200,
                            response=f"Error sending message to Slack: {str(e)}",
                            content_type="text/plain",
                        )
                except Exception as e:
                    err_msg = str(e)
                    err_trace = traceback.format_exc()

                    skip_timeout_error = settings.get("skip_timeout_error", False)
                    if (
                        skip_timeout_error
                        and "invocation exited without response" in err_msg.lower()
                    ):
                        return Response(
                            status=200,
                            response="ok",
                            content_type="text/plain",
                        )
                    else:
                        # Send error message to Slack
                        try:
                            client.chat_postMessage(
                                channel=channel,
                                thread_ts=thread_ts,
                                text=f"Sorry, I'm having trouble processing your request. Please try again later. Error: {err_msg}",
                            )
                            
                        except SlackApiError:
                            # Failed to send error message
                            pass
                        
                        # Check if storage size limit exceeded and cleanup if needed
                        if "allocated size is greater than max storage size" in err_msg.lower():
                            try:
                                self._cleanup_storage(cleanup_percentage=0.5)
                                # Send cleanup notification
                                client.chat_postMessage(
                                    channel=channel,
                                    thread_ts=thread_ts,
                                    text="🧹 Storage cleanup completed. Please try your request again.",
                                )
                            except Exception as cleanup_error:
                                print(f"Error during storage cleanup: {cleanup_error}")
                                try:
                                    client.chat_postMessage(
                                        channel=channel,
                                        thread_ts=thread_ts,
                                        text="⚠️ Storage cleanup failed. Please contact administrator.",
                                    )
                                except SlackApiError:
                                    pass

                        return Response(
                            status=200,
                            response=f"An error occurred: {err_msg}\n{err_trace}",
                            content_type="text/plain",
                        )
            elif event.get("type") == "message":
                channel = event.get("channel", "")
                thread_ts = event.get("thread_ts") or event.get("ts")
                recognized = False
                key_to_check = f"slack-{channel}-{thread_ts}"
                try:
                    if self.session.storage.get(key_to_check):
                        recognized = True
                except Exception:
                    pass
                if not recognized:
                    try:
                        if self.session.storage.get(
                            f"{self.CACHE_PREFIX}-{channel}-{thread_ts}"
                        ):
                            recognized = True
                    except Exception:
                        pass
                if recognized:
                    self._append_thread_message(
                        channel,
                        thread_ts,
                        {
                            "ts": event.get("ts"),
                            "text": event.get("text", ""),
                            "user": event.get("user"),
                            "bot_id": event.get("bot_id"),
                        },
                    )
                return Response(status=200, response="ok")
            else:
                # Other event types we're not handling
                return Response(status=200, response="ok")
        else:
            # Not an event we're handling
            return Response(status=200, response="ok")
