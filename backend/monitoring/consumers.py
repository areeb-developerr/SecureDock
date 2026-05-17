import json
from channels.generic.websocket import AsyncWebsocketConsumer


class EventConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer that streams Falco events and alerts in real-time."""

    async def connect(self):
        await self.channel_layer.group_add('events', self.channel_name)
        await self.accept()
        await self.send(text_data=json.dumps({
            'kind': 'connected',
            'message': 'Connected to SecureDock real-time event stream',
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard('events', self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # Clients don't send data; this is a broadcast-only channel
        pass

    async def event_message(self, event):
        """Handler for messages sent to the 'events' group."""
        await self.send(text_data=json.dumps(event['data']))
