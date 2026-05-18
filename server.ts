import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// Environment variables
const UUID = Deno.env.get("UUID") || "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = Deno.env.get("DOMAIN") || "your-app.railway.app";
const WS_PATH = Deno.env.get("WS_PATH") || "ws";
const SSH_PATH = Deno.env.get("SSH_PATH") || "ssh-ws";
const SUB_PATH = Deno.env.get("SUB_PATH") || "sub";
const PORT = parseInt(Deno.env.get("PORT") || "3000");

// SSH Authentication
const SSH_USER = Deno.env.get("SSH_USER") || "admin";
const SSH_PASS = Deno.env.get("SSH_PASS") || "changeme";
const SSH_AUTH_KEY = Deno.env.get("SSH_AUTH_KEY") || "my-secret-payload-key";

// ---------------- UUID utils ----------------

function parseUUID(uuid: string): Uint8Array {
  uuid = uuid.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(uuid.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------- VLESS header parser ----------------

async function parseVLESSHeader(data: Uint8Array) {
  const version = data[0];
  const id = data.slice(1, 17);

  if (!uuidEqual(id, parseUUID(UUID))) {
    throw new Error("Invalid UUID");
  }

  const optLen = data[17];
  const cmd = data[18 + optLen];

  if (cmd !== 1) throw new Error("Only TCP supported");

  const portIndex = 19 + optLen;
  const port = (data[portIndex] << 8) + data[portIndex + 1];
  const addrType = data[portIndex + 2];

  let host = "";
  let addrIndex = portIndex + 3;

  if (addrType === 1) {
    host = `${data[addrIndex]}.${data[addrIndex + 1]}.${data[addrIndex + 2]}.${data[addrIndex + 3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    const len = data[addrIndex];
    addrIndex++;
    host = new TextDecoder().decode(data.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(
        ((data[addrIndex + i * 2] << 8) + data[addrIndex + i * 2 + 1]).toString(16)
      );
    }
    host = parts.join(":");
    addrIndex += 16;
  }

  const rest = data.slice(addrIndex);

  return {
    version,
    host,
    port,
    rest,
  };
}

// ---------------- SSH Auth Handler ----------------

interface SSHAuthPayload {
  user: string;
  pass?: string;
  key?: string;
  timestamp?: number;
}

async function authenticateSSH(payload: string): Promise<boolean> {
  try {
    // Try parsing as JSON first
    let auth: SSHAuthPayload;
    
    try {
      auth = JSON.parse(payload);
    } catch {
      // If not JSON, try legacy payload format: user:pass
      const parts = payload.split(":");
      auth = { user: parts[0], pass: parts.slice(1).join(":") };
    }

    // Method 1: Username + Password authentication
    if (auth.user === SSH_USER && auth.pass === SSH_PASS) {
      return true;
    }

    // Method 2: Payload key authentication
    if (auth.key === SSH_AUTH_KEY) {
      return true;
    }

    // Method 3: Username only with predefined key
    if (auth.user === SSH_USER && payload.includes(SSH_AUTH_KEY)) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

// ---------------- SSH WebSocket Handler ----------------

async function handleSSHWS(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);
  
  let isAuthenticated = false;
  let targetConn: Deno.Conn | null = null;
  let authTimeout: number | null = null;

  socket.onopen = () => {
    console.log("SSH WebSocket connection established");
    
    // Set authentication timeout (30 seconds)
    authTimeout = setTimeout(() => {
      if (!isAuthenticated) {
        console.log("SSH authentication timeout");
        socket.send(JSON.stringify({ 
          type: "error", 
          message: "Authentication timeout" 
        }));
        socket.close();
      }
    }, 30000);
    
    // Request authentication
    socket.send(JSON.stringify({ 
      type: "auth_request", 
      message: "Please authenticate" 
    }));
  };

  socket.onmessage = async (event) => {
    try {
      const data = typeof event.data === "string" ? event.data : new TextDecoder().decode(event.data);

      // Handle authentication phase
      if (!isAuthenticated) {
        // Check if message is a JSON auth payload
        if (data.startsWith("{")) {
          if (await authenticateSSH(data)) {
            isAuthenticated = true;
            if (authTimeout) clearTimeout(authTimeout);
            
            const authPayload = JSON.parse(data);
            const targetHost = authPayload.host || "localhost";
            const targetPort = authPayload.port || 22;

            try {
              targetConn = await Deno.connect({
                hostname: targetHost,
                port: targetPort,
              });

              socket.send(JSON.stringify({ 
                type: "auth_success", 
                message: "Authenticated successfully",
                target: `${targetHost}:${targetPort}`
              }));

              // Start forwarding data from target to WebSocket
              (async () => {
                const buffer = new Uint8Array(4096);
                while (targetConn) {
                  try {
                    const n = await targetConn.read(buffer);
                    if (!n) break;
                    socket.send(buffer.slice(0, n));
                  } catch {
                    break;
                  }
                }
                if (targetConn) {
                  targetConn.close();
                  targetConn = null;
                }
                socket.close();
              })();

            } catch (err) {
              console.error("Failed to connect to target:", err);
              socket.send(JSON.stringify({ 
                type: "error", 
                message: "Failed to connect to target host" 
              }));
              socket.close();
            }
          } else {
            socket.send(JSON.stringify({ 
              type: "auth_failed", 
              message: "Invalid credentials" 
            }));
            socket.close();
          }
        } else {
          // Check legacy text-based password
          if (data === SSH_PASS || data === SSH_AUTH_KEY) {
            isAuthenticated = true;
            if (authTimeout) clearTimeout(authTimeout);
            
            // Default to localhost:22 for legacy auth
            try {
              targetConn = await Deno.connect({
                hostname: "localhost",
                port: 22,
              });

              socket.send(JSON.stringify({ 
                type: "auth_success", 
                message: "Authenticated successfully",
                target: "localhost:22"
              }));

              // Start forwarding
              (async () => {
                const buffer = new Uint8Array(4096);
                while (targetConn) {
                  try {
                    const n = await targetConn.read(buffer);
                    if (!n) break;
                    socket.send(buffer.slice(0, n));
                  } catch {
                    break;
                  }
                }
                if (targetConn) {
                  targetConn.close();
                  targetConn = null;
                }
                socket.close();
              })();

            } catch (err) {
              console.error("Failed to connect to target:", err);
              socket.close();
            }
          } else {
            socket.send(JSON.stringify({ 
              type: "auth_failed", 
              message: "Invalid password or key" 
            }));
            socket.close();
          }
        }
      } else {
        // Forward data from WebSocket to target
        if (targetConn) {
          const dataBytes = typeof event.data === "string" 
            ? new TextEncoder().encode(event.data) 
            : new Uint8Array(event.data);
          
          try {
            await targetConn.write(dataBytes);
          } catch (err) {
            console.error("Write error:", err);
            socket.close();
          }
        }
      }
    } catch (err) {
      console.error("Message handling error:", err);
      socket.close();
    }
  };

  socket.onclose = () => {
    if (authTimeout) clearTimeout(authTimeout);
    if (targetConn) {
      targetConn.close();
      targetConn = null;
    }
    console.log("SSH WebSocket connection closed");
  };

  socket.onerror = (err) => {
    console.error("SSH WebSocket error:", err);
  };

  return response;
}

// ---------------- VLESS WebSocket Handler ----------------

async function handleWS(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);

  socket.onmessage = async (event) => {
    try {
      const data = new Uint8Array(event.data);

      const vless = await parseVLESSHeader(data);

      const conn = await Deno.connect({
        hostname: vless.host,
        port: vless.port,
      });

      // send response header
      socket.send(new Uint8Array([vless.version, 0]));

      // send remaining payload
      if (vless.rest.length > 0) {
        await conn.write(vless.rest);
      }

      // pipe remote → ws
      (async () => {
        const buffer = new Uint8Array(4096);
        while (true) {
          const n = await conn.read(buffer);
          if (!n) break;
          socket.send(buffer.slice(0, n));
        }
        socket.close();
        conn.close();
      })();

      // pipe ws → remote
      socket.onmessage = async (ev) => {
        await conn.write(new Uint8Array(ev.data));
      };

      socket.onclose = () => {
        conn.close();
      };
    } catch (err) {
      socket.close();
    }
  };

  return response;
}

// ---------------- Server ----------------

serve(
  async (req: Request) => {
    const url = new URL(req.url);

    // Health check endpoint
    if (url.pathname === "/") {
      return new Response(JSON.stringify({
        status: "running",
        services: {
          vless: `wss://${DOMAIN}/${WS_PATH}`,
          ssh: `wss://${DOMAIN}/${SSH_PATH}`,
          subscription: `https://${DOMAIN}/${SUB_PATH}`
        }
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // VLESS subscription endpoint
    if (url.pathname === `/${SUB_PATH}`) {
      const vless =
        `vless://${UUID}@${DOMAIN}:443` +
        `?encryption=none` +
        `&security=tls` +
        `&type=ws` +
        `&host=${DOMAIN}` +
        `&path=/${WS_PATH}` +
        `&sni=${DOMAIN}` +
        `#VLESS-WS-Deno`;

      return new Response(btoa(vless), {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // SSH WebSocket endpoint
    if (url.pathname === `/${SSH_PATH}`) {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response(JSON.stringify({
          error: "Expected WebSocket connection",
          usage: `Connect using WebSocket to this endpoint with authentication payload`
        }), { 
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      return handleSSHWS(req);
    }

    // VLESS WebSocket endpoint
    if (url.pathname === `/${WS_PATH}`) {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 400 });
      }
      return handleWS(req);
    }

    return new Response("Not Found", { status: 404 });
  },
  { port: PORT },
);

console.log(`Server running on port ${PORT}`);
