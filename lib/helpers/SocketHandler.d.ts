import { Server, Socket } from "socket.io";
import { EventsMap, ReservedOrUserListener } from "socket.io/dist/typed-events";


// export const handleSocketPlug: Server['on'];

export function handleSocketPlug(path: string, callback: (socket: Socket, response: any) => void): (socket: Socket) => void;