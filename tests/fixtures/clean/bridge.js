// A well-behaved local WebSocket bridge fixture — mcpscan should report
// nothing here.

// MCP022: bound to loopback only, and the connection handler validates the
// Origin header before accepting the upgrade — stays quiet.
const wss = new WebSocketServer({ host: "127.0.0.1", port: 9000 });

wss.on("connection", (ws, req) => {
  if (req.headers.origin !== "https://trusted.example.com") {
    ws.close();
    return;
  }
  ws.on("message", (data) => {
    runDesktopCommand(JSON.parse(data));
  });
});
