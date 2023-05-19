export const handleSocketPlug = (path, callback) => (socket) => {
    socket.on(path, res => {
        callback(socket, res);
    });
}