export const handleSocketPlug = (path, callback) => (socket, scope) => {
    socket.on(path, function () {
        callback(socket, scope, ...arguments);
    });
}