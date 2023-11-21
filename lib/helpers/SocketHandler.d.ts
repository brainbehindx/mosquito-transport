import { Socket } from "socket.io";


// export const handleSocketPlug: Server['on'];

export function handleSocketPlug(path: string, callback: (socket: Socket, roof?: any, ...response: any) => void): (socket: Socket) => void;