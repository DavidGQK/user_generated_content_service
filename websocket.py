import asyncio

import websockets

peoples = {}  # for users nicknames


async def welcome(websocket: websockets.WebSocketServerProtocol) -> str:
    await websocket.send('What is you name?')
    name = await websocket.recv() 
    await websocket.send('For speaking write "<name>: <message>". e.g.: Kate: buy a box of juice.')
    await websocket.send('For viewing the list of users use "?"')
    peoples[name.strip()] = websocket
    return name


async def receiver(websocket: websockets.WebSocketServerProtocol, path: str) -> None: 
    name = await welcome(websocket)
    while True:
        message = (await websocket.recv()).strip()
        if message == '?':
            await websocket.send(', '.join(peoples.keys()))
            continue
        else:
            to, text = message.split(': ', 1)
            if to in peoples:
                await peoples[to].send(f'Message from {name}: {text}') 
            else:
                await websocket.send(f'User {to} does not exist')


# Creating server for processing
ws_server = websockets.serve(receiver, "localhost", 8765)

# Start event-loop
loop = asyncio.get_event_loop()
loop.run_until_complete(ws_server)
loop.run_forever()
