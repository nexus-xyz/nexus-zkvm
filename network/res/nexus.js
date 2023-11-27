const socket = new WebSocket("ws://localhost:8080/stats");

socket.addEventListener("open", (event) => {
    console.log("Websocket opened");
    socket.send("hello");
});

socket.addEventListener("close", (event) => {
    console.log("Websocket closed");
});

// Listen for messages
socket.addEventListener("message", (event) => {
    console.log("Message from server ", event.data);
});

