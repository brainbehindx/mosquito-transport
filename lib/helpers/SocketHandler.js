export const handleSocketPlug = (path, callback) => (socket, scope) => {
    socket.on(path, res => {
        callback(socket, res, scope);
    });
}