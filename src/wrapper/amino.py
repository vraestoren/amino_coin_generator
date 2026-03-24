from hmac import new
from json import loads, dumps
from os import urandom
from uuid import uuid4
from hashlib import sha1
from typing import BinaryIO
from requests import Session
from time import time, timezone
from json_minify import json_minify
from base64 import b64encode
from websocket import create_connection
from locale import getdefaultlocale as locale


class Amino:
	def __init__(
			self,
			device_id: str = None,
			proxies: dict = None) -> None:
		self.api = "https://service.aminoapps.com/api/v1"
		self.device_id = self._device_id(
			urandom(20)) if not device_id else device_id
		self.sid = None
		self.user_id = None
		self.socket_time = 0
		self.wss = None
		self.session = Session()
		self.session.headers = {
			"NDCLANG": "en",
			"NDCDEVICEID": self.device_id,
			"AUID": str(uuid4()),
			"Accept-Language": "en-US",
			"Content-Type": "application/json; charset=utf-8",
			"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; com.narvii.amino.master/3.5.35071)",
			"Host": "service.aminoapps.com",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection": "Keep-Alive"}
		if proxies:
			self.session.proxies.update(proxies)

	def _post(self, endpoint: str, data: dict, params: dict = None) -> dict:
		serialized = dumps(data)
		self._signature(serialized)
		return self.session.post(
			f"{self.api}{endpoint}", data=serialized, params=params).json()

	def _get(self, endpoint: str, params: dict = None) -> dict:
		return self.session.get(
			f"{self.api}{endpoint}", params=params).json()

	def _delete(self, endpoint: str, params: dict = None) -> dict:
		return self.session.delete(
			f"{self.api}{endpoint}", params=params).json()

	def _timestamp(self) -> int:
		return int(time() * 1000)

	def _base_data(self) -> dict:
		return {"timestamp": self._timestamp()}

	def _signature(self, data: str) -> str:
		self.session.headers["NDC-MSG-SIG"] = b64encode(
			bytes.fromhex("52") + new(
				bytes.fromhex("EAB4F1B9E3340CD1631EDE3B587CC3EBEDF1AFA9"),
				data.encode("utf-8"),
				sha1).digest() / decode("utf-8"))
		return self.session.headers["NDC-MSG-SIG"]

	def _device_id(self, identifier: bytes) -> str:
		return ("52" +
				identifier.hex() +
				new(bytes.fromhex("AE49550458D8E7C51D566916B04888BFB8B3CA7D"), b"\x52" +
					identifier, sha1).hexdigest().upper())

	def reload_socket(self) -> None:
		data = f"{self.device_id}|{int(time() * 1000)}"
		header = {
			"NDCDEVICEID": self.device_id,
			"NDCAUTH": f"sid={self.sid}",
			"NDC-MSG-SIG": self._signature(data)
		}
		self.socket_time = time()
		if self.wss:
			try:
				self.wss.close()
			except Exception:
				pass
		self.wss = create_connection(
			f"wss://ws1.narvii.com?signbody={data.replace('|', '%7C')}", header=header)

	def listen(self) -> dict:
		if (time() - self.socket_time) > 100:
			self.reload_socket()
		while True:
			try:
				return loads(self.wss.recv())
			except BaseException:
				self.reload_socket()
				continue

	def login(
			self,
			email: str,
			password: str,
			socket: bool = True) -> dict:
		data = {
			"email": email,
			"secret": f"0 {password}",
			"deviceID": self.device_id,
			"clientType": 100,
			"action": "normal",
			"timestamp": self._timestamp()
		}
		response = self._post("/g/s/auth/login", data)
		if "sid" in response:
			self.sid = response["sid"]
			self.user_id = response["auid"]
			self.session.headers["NDCAUTH"] = f"sid={self.sid}"
			if socket:
				self.reload_socket()
		return response

	def register(
			self,
			nickname: str,
			email: str,
			password: str,
			device_id: str,
			verification_code: int) -> dict:
		data = {
			"secret": f"0 {password}",
			"deviceID": device_id,
			"email": email,
			"clientType": 100,
			"nickname": nickname,
			"latitude": 0,
			"longitude": 0,
			"address": None,
			"clientCallbackURL": "narviiapp://relogin",
			"validationContext": {
				"data": {"code": verification_code},
				"type": 1,
				"identity": email
			},
			"type": 1,
			"identity": email,
			"timestamp": self._timestamp()
		}
		return self._post("/g/s/auth/register", data)

	def register_phone(
			self,
			phone_number: str,
			nickname: str,
			password: str,
			device_id: str,
			verification_code: int) -> dict:
		data = {
			"secret": f"0 {password}",
			"deviceID": device_id,
			"clientType": 100,
			"nickname": nickname,
			"latitude": 0,
			"longitude": 0,
			"address": None,
			"clientCallbackURL": "narviiapp://relogin",
			"validationContext": {
				"data": {"code": verification_code},
				"type": 8,
				"identity": phone_number,
			},
			"timestamp": self._timestamp()
		}
		return self._post("/g/s/auth/register", data)

	def activate_account(
			self,
			email: str,
			verification_code: str) -> dict:
		data = {
			"type": 1,
			"identity": email,
			"data": {"code": verification_code},
			"deviceID": self.device_id
		}
		return self._post("/g/s/auth/activate-email", data)

	def change_password(
			self,
			password: str,
			new_password: str) -> dict:
		data = {
			"secret": f"0 {password}",
			"updateSecret": f"0 {new_password}",
			"validationContext": None,
			"deviceID": self.device_id
		}
		return self._post("/g/s/auth/change-password", data)

	def request_verify_code(
			self,
			phone_number: str = None,
			email: str = None,
			reset_password: bool = False) -> dict:
		data = {
			"deviceID": self.device_id,
			"timestamp": self._timestamp()
		}
		if email:
			data["identity"] = email
			data["type"] = 1
		if reset_password:
			data["level"] = 2
			data["purpose"] = "reset-password"
		elif phone_number:
			data["identity"] = phone_number
			data["type"] = 8
		return self._post("/g/s/auth/request-security-validation", data)

	def get_from_device_id(self, device_id: str) -> dict:
		params = {"deviceId": device_id}
		return self._get("/g/s/auid", params=params)

	def check_device_id(self, device_id: str) -> dict:
		data = {
			"deviceID": device_id,
			"bundleID": "com.narvii.amino.master",
			"clientType": 100,
			"timezone": -int(timezone) // 1000,
			"systemPushEnabled": True,
			"locale": locale()[0],
			"timestamp": self._timestamp()
		}
		return self._post("/g/s/device", data)

	def get_wallet_info(self) -> dict:
		return self._get("/g/s/wallet")

	def get_wallet_history(self, start: int = 0, size: int = 25) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get("/g/s/wallet/coin/history", params=params)

	def my_communities(self, start: int = 0, size: int = 25) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get("/g/s/community/joined", params=params)

	def watch_ad(self) -> dict:
		return self.session.post(
			f"{self.api}/g/s/wallet/ads/video/start").json()

	def get_from_code(self, code: str) -> dict:
		params = {"q": code}
		return self._get("/g/s/link-resolution", params=params)

	def get_community_info(self, ndc_id: int) -> dict:
		params = {
			"withInfluencerList": 1,
			"withTopicList": "true",
			"influencerListOrderStrategy": "fansCount"
		}
		return self._get(f"/g/s-x{ndc_id}/community/info", params=params)

	def join_community(self, ndc_id: int, invitation_id: str = None) -> dict:
		data = self._base_data()
		if invitation_id:
			data["invitationId"] = invitation_id
		return self._post(f"/x{ndc_id}/s/community/join", data)

	def check_in(
			self,
			ndc_id: int = 0,
			tz: int = -int(timezone) // 1000) -> dict:
		data = {
			"timezone": tz,
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/check-in", data)

	def lottery(self, ndc_id: int, tz: int = -int(timezone) // 1000) -> dict:
		data = {"timezone": tz, "timestamp": self._timestamp()}
		return self._post(f"/x{ndc_id}/s/check-in/lottery", data)

	def get_invite_codes(
			self,
			ndc_id: int,
			status: str = "normal",
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"status": status,
			"start": start,
			"size": size
		}
		return self._get(f"/g/s-x{ndc_id}/community/invitation", params=params)

	def get_user(self, ndc_id: int, user_id: str) -> dict:
		params = {"action": "visit"}
		return self._get(f"/x{ndc_id}/s/user-profile/{user_id}", params=params)

	def get_online_users(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"topic": f"ndtopic:x{ndc_id}:online-members",
			"start": start,
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/live-layer", params=params)

	def get_recent_users(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		params = {"type": "recent", "start": start, "size": size}
		return self._get(f"/x{ndc_id}/s/user-profile", params=params)

	def get_user_following(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get(
			f"/x{ndc_id}/s/user-profile/{user_id}/joined",
			params=params)

	def get_user_followers(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get(
			f"/x{ndc_id}/s/user-profile/{user_id}/member",
			params=params)

	def follow_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/member").json()

	def unfollow_user(self, ndc_id: int, user_id: str) -> dict:
		return self._delete(
			f"/x{ndc_id}/s/user-profile/{self.user_id}/joined/{user_id}")

	def block_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/block/{user_id}").json()

	def unblock_user(self, ndc_id: int, user_id: str) -> dict:
		return self._delete(f"/x{ndc_id}/s/block/{user_id}")

	def ban_user(
			self,
			ndc_id: int,
			user_id: str,
			reason: str,
			ban_type: int = None) -> dict:
		data = {
			"reasonType": ban_type,
			"note": {"content": reason},
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/user-profile/{user_id}/ban", data)

	def get_banned_users(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		params = {"type": "banned", "start": start, "size": size}
		return self._get(f"/x{ndc_id}/s/user-profile", params=params)

	def unban_user(self, ndc_id: int, user_id: str, reason: str) -> dict:
		data = {"note": {"content": reason}, "timestamp": self._timestamp()}
		return self._post(f"/x{ndc_id}/s/user-profile/{user_id}/unban", data)

	def give_curator(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/curator").json()

	def give_leader(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/leader").json()

	def set_activity_status(self, ndc_id: int, status: int) -> dict:
		data = {
			"onlineStatus": status,
			"duration": 86400,
			"timestamp": self._timestamp()
		}
		return self._post(
			f"/x{ndc_id}/s/user-profile/{self.user_id}/online-status", data)

	def edit_profile(
			self,
			ndc_id: int,
			nickname: str = None,
			content: str = None,
			chat_request_privilege: str = None,
			background_color: str = None,
			titles: list = None,
			colors: list = None,
			default_bubble_id: str = None) -> dict:
		data = self._base_data()
		if nickname:
			data["nickname"] = nickname
		if content:
			data["content"] = content
		if chat_request_privilege:
			data["extensions"] = {
				"privilegeOfChatInviteRequest": chat_request_privilege}
		if background_color:
			data["extensions"] = {
				"style": {
					"backgroundColor": background_color}}
		if default_bubble_id:
			data["extensions"] = {"defaultBubbleId": default_bubble_id}
		if titles or colors:
			data["extensions"] = {
				"customTitles": [
					{"title": title, "color": color} for title, color in zip(titles, colors)
				]
			}
		return self._post(f"/x{ndc_id}/s/user-profile/{self.user_id}", data)

	def get_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self._get(f"/x{ndc_id}/s/chat/thread/{chat_id}")

	def get_chat_messages(
			self,
			ndc_id: int,
			chat_id: str,
			size: int = 10) -> dict:
		params = {"v": 2, "pagingType": "t", "size": size}
		return self._get(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/message",
			params=params)

	def get_chat_users(
			self,
			ndc_id: int,
			chat_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"type": "default",
			"start": start,
			"size": size
		}
		return self._get(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/member",
			params=params)

	def my_chat_threads(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"type": "joined-me",
			"start": start,
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/chat/thread", params=params)

	def get_public_chat_threads(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 10) -> dict:
		params = {
			"ndcId": f"x{ndc_id}",
			"start": start,
			"size": size
		}
		return self._get("/chat/live-threads", params=params)

	def search_user_chat(self, ndc_id: int, user_id: str) -> dict:
		params = {
			"type": "exist-single",
			"cv": "1.2",
			"q": user_id
		}
		return self._get(f"/x{ndc_id}/s/chat/thread", params=params)

	def create_chat_thread(
			self,
			ndc_id: int,
			message: str,
			user_id: str) -> dict:
		data = {
			"inviteeUids": [user_id],
			"initialMessageContent": message,
			"type": 0,
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/chat/thread", data)

	def join_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}").json()

	def leave_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self._delete(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}")

	def delete_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self._delete(f"/x{ndc_id}/s/chat/thread/{chat_id}")

	def invite_to_chat(self, ndc_id: int, chat_id: str, user_id) -> dict:
		user_ids = [user_id] if isinstance(user_id, str) else user_id
		data = {"uids": user_ids, "timestamp": self._timestamp()}
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/member/invite", data)

	def kick_user(
			self,
			ndc_id: int,
			chat_id: str,
			user_id: str,
			allow_rejoin: int = 0) -> dict:
		params = {"allowRejoin": allow_rejoin}
		return self._delete(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/member/{user_id}",
			params=params)

	def accept_host(self, ndc_id: int, chat_id: str) -> dict:
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/accept-organizer",
			self._base_data())

	def transfer_host(self, ndc_id: int, chat_id: str, user_ids: list) -> dict:
		data = {
			"uidList": user_ids,
			"timestamp": self._timestamp()
		}
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/transfer-organizer", data)

	def edit_chat(
			self,
			ndc_id: int,
			chat_id: str,
			content: str = None,
			title: str = None,
			background_image: str = None) -> dict:
		responses = []
		if background_image:
			bg_data = {
				"media": [100, background_image, None],
				"timestamp": self._timestamp()
			}
			responses.append(self._post(
				f"/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}/background",
				bg_data))
		data = self._base_data()
		if content:
			data["content"] = content
		if title:
			data["title"] = title
		responses.append(
			self._post(
				f"/x{ndc_id}/s/chat/thread/{chat_id}",
				data))
		return responses

	def change_vc_permission(
			self,
			ndc_id: int,
			chat_id: str,
			permission: int) -> dict:
		data = {
			"vvChatJoinType": permission,
			"timestamp": self._timestamp()
		}
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/vvchat-permission", data)

	def invite_to_vc(self, ndc_id: int, chat_id: str, user_id: str) -> dict:
		data = {"uid": user_id}
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/vvchat-presenter/invite", data)

	def thank_tip(self, ndc_id: int, chat_id: str, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/tipping/tipped-users/{user_id}/thank").json()

	def send_message(
			self,
			ndc_id: int,
			chat_id: str,
			message: str,
			message_type: int = 0,
			reply_message_id: str = None,
			notification: list = None) -> dict:
		data = {
			"content": message,
			"type": message_type,
			"clientRefId": int(time() / 10 % 1000000000),
			"mentionedArray": notification,
			"timestamp": self._timestamp()
		}
		if reply_message_id:
			data["replyMessageId"] = reply_message_id
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/message", data)

	def send_image(self, ndc_id: int, chat_id: str, image: str) -> dict:
		data = {
			"type": 0,
			"clientRefId": int(
				time() /
				10 %
				1000000000),
			"timestamp": self._timestamp(),
			"mediaType": 100,
			"mediaUploadValue": b64encode(
				open(
					image,
					"rb").read()).strip().decode(),
			"mediaUploadValueContentType": "image/jpg",
			"mediaUhqEnabled": False,
			"attachedObject": None}
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/message", data)

	def send_audio(self, path: str, ndc_id: int, chat_id: str) -> dict:
		data = {
			"content": None,
			"type": 2,
			"clientRefId": int(time() / 10 % 1000000000),
			"timestamp": self._timestamp(),
			"mediaType": 110,
			"mediaUploadValue": b64encode(open(path, "rb").read()).decode(),
			"attachedObject": None
		}
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/message", data)

	def send_gif(self, ndc_id: int, chat_id: str, gif: str) -> dict:
		data = {
			"type": 0,
			"clientRefId": int(
				time() /
				10 %
				1000000000),
			"timestamp": self._timestamp(),
			"mediaType": 100,
			"mediaUploadValue": b64encode(
				open(
					gif,
					"rb").read()).strip().decode(),
			"mediaUploadValueContentType": "image/gif",
			"mediaUhqEnabled": False,
			"attachedObject": None}
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/message", data)

	def send_embed(
			self,
			ndc_id: int,
			chat_id: str,
			link: str = None,
			message: str = None,
			embed_title: str = None,
			embed_content: str = None,
			embed_image: BinaryIO = None) -> dict:
		data = {
			"type": 0,
			"content": message,
			"clientRefId": int(time() / 10 % 1000000000),
			"attachedObject": {
				"objectId": None,
				"objectType": 100,
				"link": link,
				"title": embed_title,
				"content": embed_content,
				"mediaList": embed_image
			},
			"extensions": {"mentionedArray": None},
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/message", data)

	def delete_message(
			self,
			ndc_id: int,
			chat_id: str,
			message_id: str,
			reason: str = None,
			as_staff: bool = False) -> dict:
		if as_staff:
			return self._delete(
				f"/x{ndc_id}/s/chat/thread/{chat_id}/message/{message_id}/admin")
		data = {
			"adminOpName": 102,
			"adminOpNote": {"content": reason},
			"timestamp": self._timestamp()
		}
		return self._post(
			f"/x{ndc_id}/s/chat/thread/{chat_id}/message/{message_id}", data)

	def get_notifications(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 10) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/notification", params=params)

	def delete_notification(self, ndc_id: int, notification_id: str) -> dict:
		return self._delete(f"/x{ndc_id}/s/notification/{notification_id}")

	def clear_notifications(self, ndc_id: int) -> dict:
		return self._delete(f"/x{ndc_id}/s/notification")

	def get_blog_info(self, ndc_id: int, blog_id: str) -> dict:
		return self._get(f"/x{ndc_id}/s/blog/{blog_id}")

	def get_user_blogs(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"type": "user",
			"q": user_id,
			"start": start,
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/blog", params=params)

	def get_recent_blogs(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 10) -> dict:
		params = {
			"pagingType": "t",
			"start": start,
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/feed/blog-all", params=params)

	def get_tipped_users_wall(
			self,
			ndc_id: int,
			blog_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		params = {
			"start": start,
			"size": size
		}
		return self._get(
			f"/x{ndc_id}/s/blog/{blog_id}/tipping/tipped-users-summary",
			params=params)

	def like_blog(self, ndc_id: int, blog_id: str) -> dict:
		data = {
			"value": 4,
			"eventSource": "UserProfileView",
			"timestamp": self._timestamp()
		}
		params = {
			"cv": "1.2"
		}
		return self._post(
			f"/x{ndc_id}/s/blog/{blog_id}/vote",
			data,
			params=params)

	def post_blog(
			self,
			ndc_id: int,
			title: str,
			content: str,
			image_list: list = None,
			caption_list: list = None,
			categories_list: list = None,
			background_color: str = None,
			fans_only: bool = False,
			extensions: dict = None) -> dict:
		media_list = []
		if image_list:
			if caption_list:
				for image, caption in zip(image_list, caption_list):
					media_list.append(
						[100, self.upload_media(image, "image"), caption])
			else:
				for image in image_list:
					media_list.append(
						[100, self.upload_media(image, "image"), None])
		data = {
			"address": None,
			"content": content,
			"title": title,
			"mediaList": media_list,
			"extensions": extensions,
			"latitude": 0,
			"longitude": 0,
			"eventSource": "GlobalComposeMenu",
			"timestamp": self._timestamp()
		}
		if fans_only:
			data["extensions"] = {"fansOnly": fans_only}
		if background_color:
			data["extensions"] = {
				"style": {
					"backgroundColor": background_color}}
		if categories_list:
			data["taggedBlogCategoryIdList"] = categories_list
		return self._post(f"/x{ndc_id}/s/blog", data)

	def repost_blog(
			self,
			ndc_id: int,
			content: str = None,
			blog_id: str = None,
			wiki_id: str = None) -> dict:
		if blog_id:
			ref_object_id = blog_id
			ref_object_type = 1
		elif wiki_id:
			ref_object_id = wiki_id
			ref_object_type = 2
		else:
			raise ValueError("Either blog_id or wiki_id must be provided.")
		data = {
			"content": content,
			"refObjectId": ref_object_id,
			"refObjectType": ref_object_type,
			"type": 2,
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/blog", data)

	def send_coins_blog(
			self,
			ndc_id: int,
			blog_id: str,
			coins: int,
			transaction_id: str = None) -> dict:
		if transaction_id is None:
			transaction_id = str(uuid4())
		data = {
			"coins": coins,
			"tippingContext": {"transactionId": transaction_id},
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/blog/{blog_id}/tipping", data)

	def send_coins_chat(
			self,
			ndc_id: int,
			chat_id: str,
			coins: int,
			transaction_id: str = None) -> dict:
		if transaction_id is None:
			transaction_id = str(uuid4())
		data = {
			"coins": coins,
			"tippingContext": {"transactionId": transaction_id},
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/chat/thread/{chat_id}/tipping", data)

	def send_active_object(
			self,
			ndc_id: int,
			start_time: int = None,
			end_time: int = None,
			timers: list = None) -> dict:
		data = {
			"userActiveTimeChunkList": timers if timers else [{"start": start_time, "end": end_time}],
			"timestamp": self._timestamp(),
			"optInAdsFlags": 2147483647,
			"timezone": -timezone // 1000
		}
		data = json_minify(dumps(data))
		self._signature(serialized)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/community/stats/user-active-time", data=data).json()

	def create_sticker_pack(
			self,
			ndc_id: int,
			name: str,
			stickers: list) -> dict:
		data = {
			"collectionType": 3,
			"description": "sticker_pack",
			"iconSourceStickerIndex": 0,
			"name": name,
			"stickerList": stickers,
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/sticker-collection", data)

	def get_bubble_info(self, ndc_id: int, bubble_id: str) -> dict:
		return self._get(f"/x{ndc_id}/s/chat/chat-bubble/{bubble_id}")

	def buy_bubble(self, ndc_id: int, bubble_id: str) -> dict:
		data = {
			"objectId": bubble_id,
			"objectType": 116,
			"v": 1,
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/store/purchase", data)

	def comment_profile(self, ndc_id: int, content: str, user_id: str) -> dict:
		data = {
			"content": content,
			"mediaList": [],
			"eventSource": "PostDetailView",
			"timestamp": self._timestamp()
		}
		return self._post(f"/x{ndc_id}/s/user-profile/{user_id}/comment", data)

	def moderation_history_community(
			self, ndc_id: int, size: int = 25) -> dict:
		params = {
			"pagingType": "t",
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/admin/operation", params=params)

	def moderation_history_user(
			self,
			ndc_id: int,
			user_id: str = None,
			size: int = 25) -> dict:
		params = {
			"objectId": user_id,
			"objectType": 0,
			"pagingType": "t",
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/admin/operation", params=params)

	def moderation_history_blog(
			self,
			ndc_id: int,
			blog_id: str,
			size: int = 25) -> dict:
		params = {
			"objectId": blog_id,
			"objectType": 1,
			"pagingType": "t",
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/admin/operation", params=params)

	def moderation_history_quiz(
			self,
			ndc_id: int,
			quiz_id: str,
			size: int = 25) -> dict:
		params = {
			"objectId": quiz_id,
			"objectType": 1,
			"pagingType": "t",
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/admin/operation", params=params)

	def moderation_history_wiki(
			self,
			ndc_id: int,
			wiki_id: str,
			size: int = 25) -> dict:
		params = {
			"objectId": wiki_id,
			"objectType": 2,
			"pagingType": "t",
			"size": size
		}
		return self._get(f"/x{ndc_id}/s/admin/operation", params=params)
