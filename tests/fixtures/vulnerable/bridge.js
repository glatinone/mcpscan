// Intentionally vulnerable local WebSocket bridge fixture. Do not use.

// MCP022: bound to loopback only (looks safe), but the connection handler
// never checks the Origin header before accepting the upgrade — any page
// open in the same browser can connect and send commands.
const wss = new WebSocketServer({ host: "127.0.0.1", port: 9000 });

wss.on("connection", (ws, req) => {
  ws.on("message", (data) => {
    runDesktopCommand(JSON.parse(data));
  });
});
