import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function startServer() {
  const app = express();
  const server = createServer(app);
  const io = new Server(server, {
    cors: { origin: "*" }
  });

  const PORT = 3000;

  // In-memory mapping: publicKey -> socketId
  const users = new Map<string, string>();

  io.on("connection", (socket) => {
    console.log(`[SOCKET CONNECTED] ${socket.id}`);
    
    // Reverse lookup helper
    let userPublicKey: string | null = null;

    // 1. Register Public Key -> Socket ID mapping
    socket.on("register", (publicKey: string) => {
      userPublicKey = publicKey;
      users.set(publicKey, socket.id);
      console.log(`[REGISTERED] Key: ...${publicKey.slice(-5)} -> Socket: ${socket.id}`);
    });

    // 2. Blind Relay
    socket.on("message", (payload: { to: string; from: string; data: string }) => {
      const targetSocketId = users.get(payload.to);
      if (targetSocketId) {
        // Emit only to the target socket
        io.to(targetSocketId).emit("receive", {
          fromPublicKey: payload.from, // So the receiver knows who it's from
          data: payload.data
        });
        // Note: No console log of payload.data to maintain blind relay integrity
      } else {
        // Optional: Notify sender that target is offline
        // console.log(`[RELAY FAILED] Target not found: ...${payload.to.slice(-5)}`);
      }
    });

    // 3. Disconnect Handling (Volatile RAM hygiene)
    socket.on("disconnect", () => {
      console.log(`[SOCKET DISCONNECTED] ${socket.id}`);
      if (userPublicKey) {
        users.delete(userPublicKey);
      }
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
