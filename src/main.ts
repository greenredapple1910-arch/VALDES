import './index.css';
import { generateKeyPair, importKey, deriveSharedSecret, encryptMessage, decryptMessage } from './crypto';
import { io, Socket } from 'socket.io-client';

// --- VOLATILE STATE (Zero-Persistence) ---
interface Message {
  text: string;
  isMine: boolean;
  timestamp: Date;
}

interface Session {
  peerPublicKeyBase64: string;
  peerPublicKey: CryptoKey;
  sharedAesKey: CryptoKey;
  messages: Message[];
}

interface AppStateStructure {
  localPrivateKeyBase64: string | null;
  localPublicKeyBase64: string | null;
  localPrivateKey: CryptoKey | null;
  sessions: Map<string, Session>;
  activeSessionId: string | null;
  socket: Socket | null;
}

const AppState: AppStateStructure = {
  localPrivateKeyBase64: null,
  localPublicKeyBase64: null,
  localPrivateKey: null,
  sessions: new Map(),
  activeSessionId: null,
  socket: null,
};


// --- DOM ELEMENTS ---
const screenAuth = document.getElementById('screen-auth') as HTMLDivElement;
const screenChatList = document.getElementById('screen-chat-list') as HTMLDivElement;
const screenChat = document.getElementById('screen-chat') as HTMLDivElement;

const authForm = document.getElementById('auth-form') as HTMLFormElement;
const inputPrivateKey = document.getElementById('input-private-key') as HTMLInputElement;
// The "GENERATE NEW KEY PAIR" button
const btnGeneratePair = document.querySelector('#screen-auth button[type="button"]') as HTMLButtonElement;

const newChatForm = document.getElementById('new-chat-form') as HTMLFormElement;
const inputPublicKey = document.getElementById('input-public-key') as HTMLInputElement;

const chatListContainer = document.querySelector('#screen-chat-list .custom-scrollbar') as HTMLDivElement;
const chatListProfileName = document.querySelector('#screen-chat-list h1.truncate') as HTMLHeadingElement;
const btnLogout = document.getElementById('btn-logout') as HTMLButtonElement;

const chatContainer = document.getElementById('chat-container') as HTMLDivElement;
const chatForm = document.getElementById('chat-form') as HTMLFormElement;
const messageInput = document.getElementById('message-input') as HTMLTextAreaElement;
const btnBackToList = document.getElementById('btn-back-to-list') as HTMLButtonElement;
const chatHeaderTitle = document.querySelector('#screen-chat h1.truncate') as HTMLHeadingElement;
const clockEl = document.getElementById('clock') as HTMLSpanElement;

const btnCopyK1 = document.getElementById('btn-copy-k1') as HTMLButtonElement | null;
const btnCopyK2 = document.getElementById('btn-copy-k2') as HTMLButtonElement | null;
const btnCopyPeerK2 = document.getElementById('btn-copy-peer-k2') as HTMLButtonElement | null;

// --- CLOCK IMPL ---
function updateClock() {
  if (clockEl) {
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: false });
  }
}
setInterval(updateClock, 1000);
updateClock();

// --- ROUTING ---
function showScreen(screen: 'auth' | 'chat-list' | 'chat') {
  screenAuth.classList.add('hidden');
  screenChatList.classList.add('hidden');
  screenChat.classList.add('hidden');

  if (screen === 'auth') screenAuth.classList.remove('hidden');
  if (screen === 'chat-list') {
    renderChatList();
    screenChatList.classList.remove('hidden');
  }
  if (screen === 'chat') {
    renderChat();
    screenChat.classList.remove('hidden');
    messageInput.focus();
  }
}

// --- AUTH HANDLERS ---
btnGeneratePair.addEventListener('click', async () => {
  try {
    const keys = await generateKeyPair();
    // We bind Private and Public into a single encoded string for seamless copying.
    const comboKey = `${keys.key1}:${keys.key2}`;
    inputPrivateKey.value = comboKey;
    alert(`NEW KEY PAIR GENERATED\n\nYour Public Key (Share this to receive messages!):\n${keys.key2}`);
  } catch (err) {
    console.error(err);
    alert('Failed to generate key pair.');
  }
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const val = inputPrivateKey.value.trim();
  if (!val) return;

  try {
    // Separate private and public keys if combo mode
    let privBase64 = val;
    let pubBase64 = "UNKNOWN_PUB_KEY";
    
    if (val.includes(':')) {
      [privBase64, pubBase64] = val.split(':');
    }

    const importedPrivKey = await importKey(privBase64, 'private');
    
    // Save to volatile state
    AppState.localPrivateKeyBase64 = privBase64;
    AppState.localPublicKeyBase64 = pubBase64;
    AppState.localPrivateKey = importedPrivKey;

    if (chatListProfileName) { // XSS Safe
      chatListProfileName.textContent = '...' + pubBase64.slice(-5);
    }

    // Initialize Socket Connection
    AppState.socket = io();
    
    // Register Public Key with Server
    AppState.socket.on('connect', () => {
      AppState.socket?.emit('register', AppState.localPublicKeyBase64);
      console.log('Connected to Relay Server');
    });

    // Handle Incoming E2EE Messages
    AppState.socket.on('receive', async (payload: { fromPublicKey: string; data: string }) => {
      // 1. Find or create session using the peer's public key
      let session = AppState.sessions.get(payload.fromPublicKey);
      if (!session) {
        try {
          const peerPubCryptoKey = await importKey(payload.fromPublicKey, 'public');
          const sharedAesKey = await deriveSharedSecret(AppState.localPrivateKey!, peerPubCryptoKey);
          session = {
            peerPublicKeyBase64: payload.fromPublicKey,
            peerPublicKey: peerPubCryptoKey,
            sharedAesKey: sharedAesKey,
            messages: []
          };
          AppState.sessions.set(payload.fromPublicKey, session);
          
          // Re-render chat list to show new contact if they just messaged us
          if (!screenChatList.classList.contains('hidden')) {
             renderChatList();
          }
        } catch (err) {
          console.error("Failed to establish session for incoming message", err);
          return;
        }
      }

      // 2. Decrypt the payload
      try {
        const decryptedText = await decryptMessage(payload.data, session.sharedAesKey);
        
        // 3. Save to state and render if active
        const msg: Message = { text: decryptedText, isMine: false, timestamp: new Date() };
        session.messages.push(msg);

        if (AppState.activeSessionId === payload.fromPublicKey) {
          appendMessage(msg);
        }
      } catch (err) {
        console.error("Decryption failed for incoming message.", err);
      }
    });

    showScreen('chat-list');
  } catch (err) {
    console.error(err);
    alert('Invalid Private Key payload.');
  }
});

btnLogout.addEventListener('click', () => {
  // WIPE VOLATILE STATE
  AppState.localPrivateKeyBase64 = null;
  AppState.localPublicKeyBase64 = null;
  AppState.localPrivateKey = null;
  AppState.sessions.clear();
  AppState.activeSessionId = null;

  if (AppState.socket) {
    AppState.socket.disconnect();
    AppState.socket = null;
  }

  inputPrivateKey.value = '';
  // Native DOM clear to prevent HTML injection mechanisms completely
  while (chatListContainer.firstChild) {
    chatListContainer.removeChild(chatListContainer.firstChild);
  }
  
  showScreen('auth');
});

// --- CHAT LIST HANDLERS ---
newChatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const peerKeyBase64 = inputPublicKey.value.trim();
  if (!peerKeyBase64) return;
  if (!AppState.localPrivateKey) return alert("System Error: No local key initialized.");

  if (!AppState.sessions.has(peerKeyBase64)) {
    try {
      const peerPubCryptoKey = await importKey(peerKeyBase64, 'public');
      const sharedAesKey = await deriveSharedSecret(AppState.localPrivateKey, peerPubCryptoKey);
      
      AppState.sessions.set(peerKeyBase64, {
        peerPublicKeyBase64: peerKeyBase64,
        peerPublicKey: peerPubCryptoKey,
        sharedAesKey: sharedAesKey,
        messages: [] // New blank history
      });
    } catch (err) {
      console.error(err);
      return alert("Invalid Peer Public Key format.");
    }
  }

  inputPublicKey.value = '';
  AppState.activeSessionId = peerKeyBase64;
  showScreen('chat');
});

function renderChatList() {
  // Strict Wipe
  while (chatListContainer.firstChild) {
    chatListContainer.removeChild(chatListContainer.firstChild);
  }
  
  AppState.sessions.forEach((session, keyBase64) => {
    // 100% Native DOM Creation for strict XSS prevention
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'group w-full flex items-center px-4 py-3 border-b border-[#222] bg-transparent hover:bg-[#111] transition-colors outline-none cursor-pointer';
    
    if (AppState.activeSessionId === keyBase64) {
      btn.classList.replace('bg-transparent', 'bg-[#1a1a1a]');
      btn.classList.replace('hover:bg-[#111]', 'hover:bg-[#222]');
    }

    const flexContainer = document.createElement('div');
    flexContainer.className = 'flex items-center gap-3';

    // Dot Status indicator
    const dot = document.createElement('div');
    if (AppState.activeSessionId === keyBase64) {
      dot.className = 'w-1.5 h-1.5 rounded-full bg-white shadow-[0_0_4px_rgba(255,255,255,0.8)] flex-shrink-0 ml-[1px]';
    } else {
      dot.className = 'w-1.5 h-1.5 rounded-full border border-gray-500 bg-transparent flex-shrink-0 ml-[1px]';
    }

    // Name / ID
    const nameSpan = document.createElement('span');
    nameSpan.className = 'text-[13px] font-mono text-gray-400 group-hover:text-gray-200 tracking-wider transition-colors ml-[1px] truncate';
    nameSpan.textContent = '...' + keyBase64.slice(-5);

    if (AppState.activeSessionId === keyBase64) {
       nameSpan.classList.replace('text-gray-400', 'text-gray-200');
    }

    flexContainer.appendChild(dot);
    flexContainer.appendChild(nameSpan);
    btn.appendChild(flexContainer);

    btn.addEventListener('click', () => {
      AppState.activeSessionId = keyBase64;
      showScreen('chat');
    });

    chatListContainer.appendChild(btn);
  });
}

// --- CHAT HANDLERS ---
btnBackToList.addEventListener('click', () => {
  AppState.activeSessionId = null;
  showScreen('chat-list');
});

function renderChat() {
  const session = AppState.sessions.get(AppState.activeSessionId!);
  if (!session) return;

  chatHeaderTitle.textContent = '...' + session.peerPublicKeyBase64.slice(-5);

  // Wipe messages keeping the banner element
  while (chatContainer.children.length > 1) {
    chatContainer.lastChild?.remove();
  }

  session.messages.forEach(appendMessage);
}

function appendMessage(msg: Message, pendingStatus: boolean = false): { msgEl: HTMLDivElement, setSentIndicator: () => void } {
  const msgEl = document.createElement('div');
  msgEl.className = 'mb-4 leading-relaxed text-[13px] font-mono animate-fade-in flex flex-col gap-1';
  
  const header = document.createElement('div');
  header.className = 'text-[10px] text-gray-500 tracking-widest font-bold uppercase flex gap-1 items-center';
  
  const whoInfo = document.createElement('span');
  if (msg.isMine) {
    whoInfo.textContent = '<YOU>';
  } else {
    whoInfo.textContent = '<PEER>';
    header.classList.replace('text-gray-500', 'text-[#1c6a2e]');
  }
  
  const separator = document.createElement('span');
  separator.className = 'opacity-50';
  separator.textContent = '-';
  
  const timeStr = document.createElement('span');
  const ts = msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  timeStr.textContent = `[${ts}]`;
  
  header.appendChild(whoInfo);
  header.appendChild(separator);
  header.appendChild(timeStr);

  const statusSpan = document.createElement('span');
  statusSpan.className = 'ml-2 text-[10px] text-gray-600 font-bold';
  if (msg.isMine && pendingStatus) {
    statusSpan.textContent = '// PENDING';
    header.appendChild(statusSpan);
  }
  
  const setSentIndicator = () => {
    statusSpan.textContent = '// OK';
  };
  
  const bubble = document.createElement('div');
  bubble.className = msg.isMine 
    ? 'text-gray-200 break-words pl-2 border-l border-[#333]' 
    : 'text-[#1c6a2e] break-words pl-2 border-l border-[#1c6a2e]';
    
  // Support multi-line rendering securely
  const lines = msg.text.split('\n');
  lines.forEach((line, index) => {
    bubble.appendChild(document.createTextNode(line));
    if (index < lines.length - 1) {
      bubble.appendChild(document.createElement('br'));
    }
  });
  
  msgEl.appendChild(header);
  msgEl.appendChild(bubble);
  
  chatContainer.appendChild(msgEl);
  
  // Auto-scroll to bottom safely, wait for render
  requestAnimationFrame(() => {
    chatContainer.scrollTop = chatContainer.scrollHeight;
  });

  return { msgEl, setSentIndicator };
}

chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const text = messageInput.value.trim();
  if (!text) return;
  
  const session = AppState.sessions.get(AppState.activeSessionId!);
  if (!session) return;

  // 1. Save to local volatile state
  const msg: Message = { text, isMine: true, timestamp: new Date() };
  session.messages.push(msg);
  
  // 2. Render locally
  const { setSentIndicator } = appendMessage(msg, true);
  messageInput.value = '';

  // 3. Encrypt & Dispatch outward route
  try {
    const encryptedBase64 = await encryptMessage(text, session.sharedAesKey);
    console.log(`\n=== E2EE OUTBOUND PAYLOAD ===\nTARGET: ...${session.peerPublicKeyBase64.slice(-5)}\nPAYLOAD: ${encryptedBase64}\n===============================\n`);
    
    // Relay blind message through Socket Server
    if (AppState.socket) {
      AppState.socket.emit('message', {
        to: session.peerPublicKeyBase64,
        from: AppState.localPublicKeyBase64,
        data: encryptedBase64
      });
      // Since socket.io emit is enqueued locally, we assume it's "sent"
      setSentIndicator();
    }

  } catch (err) {
    console.error("Failed to encrypt outbound message", err);
  }
});

// Enable enter-to-submit (shift-enter allows newlines natively in textarea)
messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    chatForm.requestSubmit();
  }
});

// --- COPY HANDLERS ---
if (btnCopyK1) {
  btnCopyK1.addEventListener('click', () => {
    if (AppState.localPrivateKeyBase64) {
      navigator.clipboard.writeText(AppState.localPrivateKeyBase64)
        .then(() => alert("PRIVATE AUTH KEY COPIED. DO NOT SHARE!"))
        .catch(err => console.error("Could not copy text: ", err));
    }
  });
}

if (btnCopyK2) {
  btnCopyK2.addEventListener('click', () => {
    if (AppState.localPublicKeyBase64) {
      navigator.clipboard.writeText(AppState.localPublicKeyBase64)
        .then(() => alert("PUBLIC CONTACT KEY COPIED. SEND THIS TO PEERS."))
        .catch(err => console.error("Could not copy text: ", err));
    }
  });
}

if (btnCopyPeerK2) {
  btnCopyPeerK2.addEventListener('click', () => {
    if (AppState.activeSessionId) {
      navigator.clipboard.writeText(AppState.activeSessionId)
        .then(() => alert("PEER PUBLIC KEY COPIED."))
        .catch(err => console.error("Could not copy text: ", err));
    }
  });
}

// --- PWA SERVICE WORKER ---
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then((registration) => {
      console.log('SW registered: ', registration);
    }).catch((registrationError) => {
      console.log('SW registration failed: ', registrationError);
    });
  });
}
