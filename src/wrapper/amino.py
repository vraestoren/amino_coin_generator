from hmac import new
from json import loads
from json import dumps
from os import urandom
from uuid import uuid4
from hashlib import sha1
from typing import BinaryIO
from requests import Session
from time import time, timezone
from json_minify import json_minify
from base64 import b64encode, b64decode
from websocket import create_connection
from locale import getdefaultlocale as locale
	
class Amino:
	def __init__(
			self,
			device_id: str = None,
			proxies: dict = None) -> None:
		self.api = "https://service.aminoapps.com/api/v1"
		self.device_id = self.generate_device_id(urandom(20)) if not device_id else device_id
		self.sid = None
		self.user_id = None
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
			"Connection": "Keep-Alive"
		}
		self.session.proxies.update(proxies)

	def generate_signature(self, data: str) -> str:
		self.session.headers["NDC-MSG-SIG"] = b64encode(
			bytes.fromhex("52") + new(bytes.fromhex("EAB4F1B9E3340CD1631EDE3B587CC3EBEDF1AFA9"), data.encode("utf-8"), sha1).digest()
		).decode("utf-8")
		return self.session.headers["NDC-MSG-SIG"]
	
	def generate_device_id(self, identifier: str) -> str:
		return (
			"52" + identifier.hex() + new(bytes.fromhex("AE49550458D8E7C51D566916B04888BFB8B3CA7D"), b"\x52" + identifier, sha1).hexdigest()
		).upper()
	
	def reload_socket(self) -> None:
		data = f"{self.device_id}|{int(time() * 1000)}"
		self.websocket_headers = {
			"NDCDEVICEID": self.device_id,
			"NDCAUTH": f"sid={self.sid}",
			"NDC-MSG-SIG": self.generate_signature(data)
		}
		self.socket_time = time()
		self.ws_connection = create_connection(f"wss://ws1.narvii.com?signbody={data.replace('|', '%7C')}", header=self.websocket_headers)
  
	def login(
			self,
			email: str,
			password: str,
			socket: bool = True) -> dict:
		data = dumps({
			"email": email,
			"secret": f"0 {password}",
			"deviceID": self.device_id,
			"clientType": 100,
			"action": "normal",
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		response = self.session.post(
			f"{self.api}/g/s/auth/login", data=data).json()
		if "sid" in response:
			self.sid = response["sid"]
			self.user_id = response["auid"]
			self.session.headers["NDCAUTH"] = f"sid={self.sid}"
			if socket:
				self.reload_socket()
		return response

	def send_active_object(
			self,
			ndc_id: int,
			start_time: int = None,
			end_time: int = None,
			timers: list = None) -> dict:
		data = {
			"userActiveTimeChunkList": [
				{
					"start": start_time,
					"end": end_time
				}
			],
			"timestamp": int(time() * 1000),
			"optInAdsFlags": 2147483647,
			"timezone": -timezone // 1000
		}
		if timers:
			data["userActiveTimeChunkList"] = timers
		data = json_minify(dumps(data))
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/community/stats/user-active-time", data=data).json()

	def request_verify_code(
			self, 
			phone_number: str = None,
			email: str = None,
			reset_password: bool = False) -> dict:
		data = {
			"deviceID": self.device_id,
			"timestamp": int(time() * 1000)
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
		data = dumps(data)
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/auth/request-security-validation",
			data=data).json()
	
	def register(
			self,
			nickname: str,
			email: str, 
			password: str,
			device_id: str,
			verification_code: int) -> dict:
		data = dumps({
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
				"data": {
					"code": verification_code
				},
				"type": 1,
				"identity": email
			},
			"type": 1,
			"identity": email,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/auth/register", data=data).json()

	def get_from_device_id(self, device_id: str) -> dict:
		return self.session.get(
			f"{self.api}/g/s/auid?deviceId={device_id}").json()  

	def accept_host(self, ndc_id: int, chat_id: str) -> dict:
		data = dumps({
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/accept-organizer", data=data).json() 
		 
	def get_notifications(self, ndc_id: int, start: int = 0, size: int = 10) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/notification?start={start}&size={size}").json() 
		 
	def check_device_id(self, device_id: str) -> dict:
		data = dumps({
			"deviceID": device_id,
			"bundleID": "com.narvii.amino.master",
			"clientType": 100,
			"timezone": -int(timezone) // 1000,
			"systemPushEnabled": True,
			"locale": locale()[0],
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/device", data=data).json() 
		 
	def get_wallet_info(self) -> dict:
		return self.session.get(f"{self.api}/g/s/wallet").json() 
		 
	def get_wallet_history(
			self,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/g/s/wallet/coin/history?start={start}&size={size}").json() 
		 
	def my_communities(
			self,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/g/s/community/joined?start={start}&size={size}").json()  
		
	def watch_ad(self) -> dict:
		return self.session.post(
			f"{self.api}/g/s/wallet/ads/video/start").json() 
		 
	def transfer_host(
			self,
			ndc_id: int,
			chat_id: str,
			user_ids: list) -> dict:
		data = dumps({
			"uidList": user_ids,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/transfer-organizer",
			data=data).json()  

	def join_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}").json()  

	def get_chat_messages(
			self,
			ndc_id: int,
			chat_id: str,
			size: int = 10) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message?v=2&pagingType=t&size={size}").json() 
		 
	def get_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}").json()  

	def send_audio(
			self,
			path: str,
			ndc_id: int,
			chat_id: str) -> dict:
		data = dumps({
			"content": None,
			"type": 2,
			"clientRefId": int(time() / 10 % 1000000000),
			"timestamp": int(time() * 1000),
			"mediaType": 110,
			"mediaUploadValue": b64encode(open(path, "rb").read()),
			"attachedObject": None
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message",
			data=data).json() 
		 
	def ban_user(
			self,
			ndc_id: int,
			user_id: str,
			reason: str,
			ban_type: int = None) -> dict:
		data = dumps({
			"reasonType": ban_type,
			"note": {
				"content": reason 
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/ban",
			data=data).json() 
		 
	def get_banned_users(self, ndc_id: int, start: int = 0, size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/user-profile?type=banned&start={start}&size={size}").json()  

	def unban_user(
			self,
			ndc_id: int,
			user_id: str,
			reason: str) -> dict:
		data = dumps({
			"note": { 
				"content": reason 
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/unban",
			data=data).json() 
		 
	def create_chat_thread(
			self,
			ndc_id: int,
			message: str,
			user_id: str) -> dict:
		data = dumps({
			"inviteeUids": [user_id],
			"initialMessageContent": message,
			"type": 0,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread", data=data).json()  

	def delete_message(
			self,
			ndc_id: int,
			chat_id: str,
			message_id: str,
			reason: str = None,
			as_staff: bool = False) -> dict:
		data = dumps({
			"adminOpName": 102,
			"adminOpNote": {"content": reason},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		if as_staff:
			return self.session.delete(
				f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message/{message_id}/admin").json() 
		else:
			return self.session.post(
				f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message/{message_id}",
				data=data).json()  

	def kick_user(
			self,
			ndc_id: int,
			chat_id: str,
			user_id: str,
			allowRejoin: int = 0) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/{user_id}?allowRejoin={allowRejoin}").json()   

	def create_sticker_pack(
			self,
			ndc_id: int,
			name: str,
			stickers: list) -> dict:
		data = dumps({
			"collectionType": 3,
			"description": "sticker_pack",
			"iconSourceStickerIndex": 0,
			"name": name,
			"stickerList": stickers,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/sticker-collection", data=data).json() 
		 
	def search_user_chat(
			self,
			ndc_id: int,
			user_id: str) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/thread?type=exist-single&cv=1.2&q={user_id}").json()  

	def change_vc_permission(
			self,
			ndc_id: int,
			chat_id: str,
			permission: int) -> dict:
		data = dumps({
			"vvChatJoinType": permission,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/vvchat-permission", data=data).json()  

	def send_embed(
			self,
			ndc_id: int,
			chat_id: str,
			link: str = None,
			message: str = None,
			embed_title: str = None,
			embed_content: str = None,
			embed_image: BinaryIO = None) -> dict:
		data = dumps({
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
			"extensions": {
				"mentionedArray": None
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message", data=data).json() 
		 
	def send_message(
			self,
			ndc_id: int,
			chat_id: str,
			message: str,
			message_type: int = 0,
			reply_message_id: str = None,
			notification : list = None) -> dict:
		data = dumps({
			"content": message,
			"type": message_type,
			"clientRefId": int(time() / 10 % 1000000000),
			"mentionedArray": [notification], 
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		if reply_message_id:
			data["replyMessageId"] = reply_message_id
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message", data=data).json() 
		 
	def get_chat_users(
			self,
			ndc_id: int,
			chat_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member&type=default&start={start}&size={size}").json() 
		 
	def my_chat_threads(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/thread?type=joined-me&start={start}&size={size}").json()  

	def get_public_chat_threads(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 10) -> dict:
		return self.session.get(
			f"{self.api}/chat/live-threads?ndcId=x{ndc_id}&start={start}&size={size}").json()
		 
	def thank_tip(
			self,
			ndc_id: int,
			chat_id: str,
			user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/tipping/tipped-users/{user_id}/thank").json()  

	def get_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}?action=visit").json() 
		 
	def get_tipped_users_wall(
			self,
			ndc_id: int,
			blog_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/blog/{blog_id}/tipping/tipped-users-summary?start={start}&size={size}").json() 
		
	def send_image(
			self,
			ndc_id: int,
			chat_id: str,
			image: str) -> dict:
		data = dumps({
			"type": 0,
			"clientRefId": int(time() / 10 % 1000000000),
			"timestamp": int(time() * 1000),
			"mediaType": 100,
			"mediaUploadValue": b64encode(open(image, "rb").read()).strip().decode(),
			"mediaUploadValueContentType": "image/jpg", 
			"mediaUhqEnabled": False, 
			"attachedObject": None
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message", data=data).json() 
		 
	def join_community(
			self,
			ndc_id: int,
			invitation_id: str = None) -> dict:
		data = dumps({
			"timestamp": int(time() * 1000)
		})
		if invitation_id:
			data["invitationId"] = invitation_id
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/community/join", data=data).json() 
	
	def invite_to_chat(
			self,
			ndc_id: int,
			chat_id: str,
			user_id: [str, list]) -> dict:
		if isinstance(user_id, str):
			user_ids = [user_id]
		elif isinstance(user_id, list):
			user_ids = user_id
		data = dumps({
			"uids": user_ids,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/invite", data=data).json()  

	def get_online_users(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/live-layer?topic=ndtopic:x{ndc_id}:online-members&start={start}&size={size}").json()  

	def get_recent_users(
			self,
			ndc_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/user-profile?type=recent&start={start}&size={size}").json() 
	
	def leave_chat(
			self,
			ndc_id: int,
			chat_id: str) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}").json() 
		
	def send_gif(
			self,
			ndc_id: int,
			chat_id: str,
			gif: str) -> dict:
		data = dumps({
			"type": 0,
			"clientRefId": int(time() / 10 % 1000000000),
			"timestamp": int(time() * 1000), 
			"mediaType": 100, 
			"mediaUploadValue": b64encode(open(gif, "rb").read()).strip().decode(), 
			"mediaUploadValueContentType": "image/gif",
			"mediaUhqEnabled": False,
			"attachedObject": None
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/message", data=data).json() 

	def comment_profile(
			self,
			ndc_id: int,
			content: str,
			user_id: str) -> dict:
		data = dumps({
			"content": content,
			"mediaList": [], 
			"eventSource": "PostDetailView", 
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/comment", data=data).json() 
		 
	def get_from_code(self, code: str) -> dict:
		return self.session.get(
			f"{self.api}/g/s/link-resolution?q={code}").json() 
		 
	def get_user_blogs(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/blog?type=user&q={user_id}&start={start}&size={size}").json() 
		 
	def get_community_info(self, ndc_id: int) -> dict:
		return self.session.get(
			f"{self.api}/g/s-x{ndc_id}/community/info?withInfluencerList=1&withTopicList=true&influencerListOrderStrategy=fansCount").json() 
	
	def check_in(
			self,
			ndc_id: int = 0,
			timezone: int = -int(timezone) // 1000) -> dict:
		data = dumps({
			"timezone": timezone,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/check-in", data=data).json()  

	def send_coins_blog(
			self,
			ndc_id: int,
			blog_id: str = None, 
			coins: int = None,
			transaction_id: str = uuid4()) -> dict:
		data = dumps({
			"coins": coins,
			"tippingContext": {
				"transactionId": transaction_id
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/blog/{blog_id}/tipping", data=data).json() 
		 
	def send_coins_chat(
			self,
			ndc_id: int,
			chat_id: str = None,
			coins: int = None,
			transaction_id: str = uuid4()) -> dict:
		data = dumps({
			"coins": coins,
			"tippingContext": {
				"transactionId": transaction_id
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/tipping", data=data).json()  

	def lottery(
			self,
			ndc_id: int,
			timezone: str = -int(timezone) // 1000) -> dict:
		data = dumps({
			"timezone": timezone,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/check-in/lottery", data=data).json()  
		
	def edit_chat(
			self,
			ndc_id: int,
			chat_id: str,
			content: str = None,
			title: str = None,
			background_image: str = None) -> dict:
		response = []
		data = {
			"timestamp": int(time() * 1000)
		}
		if background_image:
			data["media"] = [100, background_image, None],
			self.generate_signature(data)
			response.append(self.session.post(
				f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/member/{self.user_id}/background",
				data=data).json())
		if content:
			data["content"] = content
		if title:
			data["title"] = title
		data = dumps(data)
		generate_signature(data)
		response.append(self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}", data=data).json())
		return response
	   
	def moderation_history_community(self, ndc_id: int, size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/admin/operation?pagingType=t&size={size}").json()  
		
	def moderation_history_user(
			self,
			ndc_id: int, 
			user_id: str = None, 
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/admin/operation?objectId={user_id}&objectType=0&pagingType=t&size={size}").json() 
		 
	def moderation_history_blog(
			self,
			ndc_id: int,
			blog_id: str,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/admin/operation?objectId={blog_id}&objectType=1&pagingType=t&size={size}").json()  
		
	def moderation_history_quiz(
			self, 
			ndc_id: int,
			quiz_id: str, 
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/admin/operation?objectId={quiz_id}&objectType=1&pagingType=t&size={size}").json()  
		
	def moderation_history_wiki(
			self, ndc_id: int,
			wiki_id: str,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/admin/operation?objectId={wiki_id}&objectType=2&pagingType=t&size={size}").json() 
		 
	def give_curator(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/curator").json()  
		
	def give_leader(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/leader").json()  
		
	def get_bubble_info(self, ndc_id: int, bubble_id: str) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/chat/chat-bubble/{bubble_id}").json() 
		 
	def buy_bubble(self, ndc_id: int, bubble_id: str) -> dict:
		data = dumps({
			"objectId": bubble_id,
			"objectType": 116,
			"v": 1,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/store/purchase", 
			data=data).json() 

	def invite_to_vc(
			self,
			ndc_id: int,
			chat_id: str,
			user_id: str) -> dict:
		data = dumps({
			"uid": user_id
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}/vvchat-presenter/invite", 
			data=data).json()  
	
	def delete_chat(self, ndc_id: int, chat_id: str) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/chat/thread/{chat_id}").json()  
	
	def delete_notification(
			self,
			ndc_id: int,
			notification_id: str) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/notification/{notificationId}").json() 
		 
	def clear_notifications(self, ndc_id: int) -> dict:
		return self.session.delete(f"{self.api}/x{ndc_id}/s/notification").json() 
		
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
		data = {
			"timestamp": int(time() * 1000)
		}
		if nickname:
			data["nickname"] = nickname
		if content:
			data["content"] = content
		if chat_request_privilege:
			data["extensions"] = {"privilegeOfChatInviteRequest": chat_request_privilege}
		if background_color:
			data["extensions"] = {"style": {"backgroundColor": background_color}}
		if default_bubble_id:
			data["extensions"] = {"defaultBubbleId": default_bubble_id}
		if titles or colors:
			titles_colors = []
			for titles, colors in zip(titles, colors):
				titles_colors.append(
					{"title": titles, "color": colors}
				)
			data["extensions"] = {"customTitles": titles_colors}
		data = dumps(data)
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{self.user_id}", data=data).json()
		 
	def activate_account(
			self,
			email: str,
			verification_code: str) -> dict:
		data = dumps({
			"type": 1,
			"identity": email,
			"data": {
				"code": verification_codE
			},
			"deviceID": self.device_id
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/auth/activate-email", data=data).json()
	
	def get_recent_blogs(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 10) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/feed/blog-all?pagingType=t&start={start}&size={size}").json()
	
	def like_blog(self, ndc_id: int, blog_id: str) -> dict:
		data = dumps({
			"value": 4,
			"eventSource": "UserProfileView",
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/blog/{blog_id}/vote?cv=1.2",
			data=data).json()

	def follow_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/member").json()
		
	def unfollow_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/user-profile/{self.user_id}/joined/{user_id}").json()
	
	def get_user_following(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/joined?start={start}&size={size}").json()

	def get_user_followers(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/user-profile/{user_id}/member?start={start}&size={size}").json()
	
	def block_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/block/{user_id}").json()
		
	def unblock_user(self, ndc_id: int, user_id: str) -> dict:
		return self.session.delete(
			f"{self.api}/x{ndc_id}/s/block/{user_id}").json()

	def get_online_users(
			self,
			ndc_id: int,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/live-layer?topic=ndtopic:x{ndc_id}:online-members&start={start}&size={size}").json()

	def get_blog_info(self, ndc_id: int, blog_id: str) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/blog/{blog_id}").json()
	
	def get_user_blogs(
			self,
			ndc_id: int,
			user_id: str,
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/x{ndc_id}/s/blog?type=user&q={user_id}&start={start}&size={size}").json()
	
	def set_activity_status(
			self,
			ndc_id: int,
			status: int) -> dict:
		"""
		STATUS-TYPES:
			1 - ONLINE,
			2 - OFFLINE
		"""
		data = dumps({
			"onlineStatus": status,
			"duration": 86400,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/user-profile/{self.user_id}/online-status",
			data=data).json()
	
	def get_invite_codes(
			self,
			ndc_id: int,
			status: str = "normal",
			start: int = 0,
			size: int = 25) -> dict:
		return self.session.get(
			f"{self.api}/g/s-x{ndc_id}/community/invitation?status={status}&start={start}&size={size}").json()
	
	def listen(self) -> dict:
		if((time() - self.socket_time) > 100):
			self.ws_connection.close()
			self.reload_socket()
		while 1:
			try:
				return loads(self.ws_connection.recv())	 
			except:
				continue

	def change_password(
			self,
			password: str,
			new_password: str) -> dict:
		data = dumps({
			"secret": f"0 {password}",
			"updateSecret": f"0 {new_password}",
			"validationContext": None,
			"deviceID": self.device_id
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/auth/change-password", data=data).json()
	
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
		if caption_list:
			for image, caption in zip(image_list, caption_list):
				media_list.append([100, self.upload_media(image, "image"), caption])
		else:
			if image_list:
				for image in image_list:
					media_list.append([100, self.upload_media(image, "image"), None])
		data = {
			"address": None,
			"content": content,
			"title": title,
			"mediaList": media_list,
			"extensions": extensions,
			"latitude": 0,
			"longitude": 0,
			"eventSource": "GlobalComposeMenu",
			"timestamp": int(time() * 1000)
		}
		
		if fans_only:
			data["extensions"] = {"fansOnly": fansOnly}
		if background_color:
			data["extensions"] = {"style": {"backgroundColor": background_color}}
		if categories_list:
			data["taggedBlogCategoryIdList"] = categories_list
		data = dumps(data)
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/blog", data=data).json()
	
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
			ref_object_id = wiki_id,
			ref_object_type = 2
		data = dumps({
			"content": content,
			"refObjectId": ref_object_id,
			"refObjectType": ref_object_type,
			"type": 2,
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/x{ndc_id}/s/blog", data=data).json()

	def register_phone(
			self,
			phone_number: str,
			nickname: str,
			password: str,
			device_id: str,
			verification_code: int) -> dict:
		data = dumps({
			"secret": f"0 {password}",
			"deviceID": device_id,
			"clientType": 100,
			"nickname": nickname,
			"latitude": 0,
			"longitude": 0,
			"address": None,
			"clientCallbackURL": "narviiapp://relogin",
			"validationContext": {
				"data": {
					"code": verification_code
				},
				"type": 8,
				"identity": phone_number,
			},
			"timestamp": int(time() * 1000)
		})
		self.generate_signature(data)
		return self.session.post(
			f"{self.api}/g/s/auth/register", data=data).json()
