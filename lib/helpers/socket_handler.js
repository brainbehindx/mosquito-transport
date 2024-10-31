
/**
 * @type {(path: string, callback: (socket: import('socket.io').Socket, roof?: any, ...args: any) => void ) => (socket: import('socket.io').Socket)=> void}
 */
export const handleSocketPlug = (path, callback) => (socket, scope) => {
    socket.on(path, function () {
        callback(socket, scope, ...arguments);
    });
};