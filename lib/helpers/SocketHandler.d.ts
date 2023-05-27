import { Socket } from "socket.io";


// export const handleSocketPlug: Server['on'];

export function handleSocketPlug(path: string, callback: (socket: Socket, response: any, roof?: any) => void): (socket: Socket) => void;