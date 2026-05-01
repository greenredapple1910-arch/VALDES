import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function startServer() {
  const app = express();
  app.set('trust proxy', true);
  const server = createServer(app);
  const io = new Server(server, {
    cors: { origin: "*" }
  });

  const PORT = 3000;

  // --- DB Initialization ---
  const db = new Database('valdes.db');
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      to_key TEXT NOT NULL,
      from_key TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const insertMsg = db.prepare('INSERT INTO messages (to_key, from_key, payload) VALUES (?, ?, ?)');
  const getHistory = db.prepare('SELECT * FROM messages WHERE to_key = ? ORDER BY created_at ASC');
  const cleanOldMsg = db.prepare('DELETE FROM messages WHERE created_at < datetime("now", "-30 days")');

  // Run GC every hour representing 30 days retention
  setInterval(() => {
    try {
      cleanOldMsg.run();
    } catch (err) {
      console.error("GC Error:", err);
    }
  }, 1000 * 60 * 60);

  // In-memory mapping: publicKey -> socketId
  const users = new Map<string, string>();

  io.on("connection", (socket) => {
    // Cloudflare Proxy IP Extraction
    const cfIp = socket.handshake.headers['cf-connecting-ip'];
    const forwardedFor = socket.handshake.headers['x-forwarded-for'];
    const rawIp = cfIp || forwardedFor || socket.handshake.address || "unknown";
    
    let realIp = Array.isArray(rawIp) ? rawIp[0] : rawIp as string;
    
    // Mask the IP for privacy (e.g. 192.168.1.***)
    let maskedIp = realIp;
    if (realIp.includes('.')) {
      const parts = realIp.split('.');
      if (parts.length === 4) {
        parts[3] = '***';
        maskedIp = parts.join('.');
      }
    } else if (realIp.includes(':')) {
      const parts = realIp.split(':');
      if (parts.length >= 3) {
        parts[parts.length - 1] = '***';
        parts[parts.length - 2] = '***';
        maskedIp = parts.join(':');
      }
    }

    console.log(`[SOCKET] Connected: ${socket.id} | IP: ${maskedIp}`);
    
    // Reverse lookup helper
    let userPublicKey: string | null = null;

    // 1. Register Public Key -> Socket ID mapping
    socket.on("register", (publicKey: string) => {
      userPublicKey = publicKey;
      users.set(publicKey, socket.id);
      console.log(`[REGISTERED] Key: ...${publicKey.slice(-5)} -> Socket: ${socket.id}`);
      
      // Dispatch persistent mailbox history to user
      try {
        const history = getHistory.all(publicKey);
        socket.emit("history", history);
      } catch (error) {
        console.error("DB Error fetching history:", error);
      }
    });

    // 2. Encrypted Mailbox and Relay
    socket.on("message", (payload: { to: string; from: string; data: string }) => {
      let insertedId: number | bigint = 0;
      try {
        const result = insertMsg.run(payload.to, payload.from, payload.data);
        insertedId = result.lastInsertRowid;
      } catch (error) {
        console.error("DB Error inserting message:", error);
        return;
      }

      const targetSocketId = users.get(payload.to);
      if (targetSocketId) {
        // Target is online, emit live
        io.to(targetSocketId).emit("receive", {
          id: insertedId,
          fromPublicKey: payload.from,
          data: payload.data,
          created_at: new Date().toISOString()
        });
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
