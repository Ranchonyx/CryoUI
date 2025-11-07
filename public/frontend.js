var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// node_modules/cryo-client-browser/dist/lib/index.js
var h = class {
  static {
    __name(this, "h");
  }
  pending = /* @__PURE__ */ new Map();
  Track(e, r) {
    this.pending.set(e, r);
  }
  Confirm(e) {
    let r = this.pending.get(e);
    return r ? (this.pending.delete(e), r) : null;
  }
  Has(e) {
    return this.pending.has(e);
  }
};
var c = class n {
  static {
    __name(this, "n");
  }
  constructor(e) {
    this.buffer = e;
    this.view = new DataView(e.buffer, e.byteOffset, e.byteLength);
  }
  view;
  static alloc(e) {
    return new n(new Uint8Array(e));
  }
  static from(e, r) {
    if (r === "utf8") return new n(new TextEncoder().encode(e));
    let s = new Uint8Array(e.length / 2);
    for (let t = 0; t < s.length; t++) s[t] = parseInt(e.substring(t * 2, t * 2 + 2), 16);
    return new n(s);
  }
  static concat(e) {
    if (e.length === 0) return n.alloc(0);
    let r = e.reduce((a, i) => a + i.length, 0), s = new Uint8Array(r), t = 0;
    for (let a of e) s.set(a.buffer, t), t += a.length;
    return new n(s);
  }
  writeUInt32BE(e, r) {
    this.view.setUint32(r, e);
  }
  writeUInt8(e, r) {
    this.view.setUint8(r, e);
  }
  readUInt32BE(e) {
    return this.view.getUint32(e);
  }
  readUInt8(e) {
    return this.view.getUint8(e);
  }
  write(e, r = 0) {
    this.buffer.set(new TextEncoder().encode(e), r);
  }
  set(e, r) {
    this.buffer.set(e.buffer, r);
  }
  toString(e) {
    return e === "utf8" ? new TextDecoder().decode(this.buffer) : [...this.buffer].map((r) => r.toString(16).padStart(2, "0")).join("");
  }
  subarray(e, r) {
    return new n(this.buffer.subarray(e, r));
  }
  copy(e, r = 0) {
    e.buffer.set(this.buffer, r);
  }
  get length() {
    return this.buffer.byteLength;
  }
};
var g = class n2 extends Error {
  static {
    __name(this, "n");
  }
  constructor(e) {
    super(e), Object.setPrototypeOf(this, n2.prototype);
  }
};
var p = class n3 {
  static {
    __name(this, "n");
  }
  static AgainstNull(e, r) {
    if (e === null) throw new g(r || `Assertion failed, "param" (${e}) was null!`);
  }
  static AgainstUndefined(e, r) {
    if (e === void 0) throw new g(r || `Assertion failed, "param" (${e}) was undefined!`);
  }
  static AgainstNullish(e, r) {
    n3.AgainstUndefined(e, r), n3.AgainstNull(e, r);
  }
  static CastAs(e) {
    n3.AgainstNullish(e);
  }
  static CastAssert(e, r, s) {
    if (n3.AgainstNullish(e, s), n3.AgainstNullish(r, s), !r) throw new g("Parameter assertion failed in CastAssert!");
  }
};
var l = class {
  static {
    __name(this, "l");
  }
  static sidFromCryoBuffer(e) {
    let r = e.subarray(0, 4).toString("hex"), s = e.subarray(4, 6).toString("hex"), t = e.subarray(6, 8).toString("hex"), a = e.subarray(8, 10).toString("hex"), i = e.subarray(10, 16).toString("hex");
    return [r, s, t, a, i].join("-");
  }
  static sidToCryoBuffer(e) {
    return c.from(e.replaceAll("-", ""), "hex");
  }
};
var w = class {
  static {
    __name(this, "w");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20);
    if (t !== 0) throw new Error("Attempt to deserialize a non-ack binary message!");
    return { sid: r, ack: s, type: t };
  }
  Serialize(e, r, s = null) {
    let t = c.alloc(21);
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(0, 20), t;
  }
};
var A = class {
  static {
    __name(this, "A");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21).toString("utf8");
    if (t !== 2) throw new Error("Attempt to deserialize a non-ping_pong binary message!");
    if (!(a === "ping" || a === "pong")) throw new Error(`Invalid payload ${a} in ping_pong binary message!`);
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    let t = c.alloc(25);
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(2, 20), t.write(s, 21), t;
  }
};
var v = class {
  static {
    __name(this, "v");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21).toString("utf8");
    if (t !== 3) throw new Error("Attempt to deserialize a non-data binary message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    let t = c.alloc(21 + (s?.length || 4));
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(3, 20), t.write(s || "null", 21), t;
  }
};
var T = class {
  static {
    __name(this, "T");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21);
    if (t !== 4) throw new Error("Attempt to deserialize a non-data binary message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    let t = s ? s.length : 4, a = c.alloc(21 + t);
    return l.sidToCryoBuffer(e).copy(a, 0), a.writeUInt32BE(r, 16), a.writeUInt8(4, 20), a.set(s || c.from("null", "utf8"), 21), a;
  }
};
var M = class {
  static {
    __name(this, "M");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21).toString("utf8");
    if (t !== 1) throw new Error("Attempt to deserialize a non-error message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    let t = c.alloc(21 + (s?.length || 13));
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(1, 20), t.write(s || "unknown_error", 21), t;
  }
};
var S = class {
  static {
    __name(this, "S");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21);
    if (t !== 5) throw new Error("Attempt to deserialize a non-server_hello message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    if (p.CastAssert(s, s !== null, "payload was null!"), s.length !== 65) throw new Error("Payload in ServerHelloMessage must be exactly 65 bytes!");
    let t = c.alloc(86);
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(5, 20), t.set(s, 21), t;
  }
};
var U = class {
  static {
    __name(this, "U");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21);
    if (t !== 6) throw new Error("Attempt to deserialize a non-client_hello message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    if (p.CastAssert(s, s !== null, "payload was null!"), s.length !== 65) throw new Error("Payload in ClientHelloMessage must be exactly 65 bytes!");
    let t = c.alloc(86);
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(6, 20), t.set(s, 21), t;
  }
};
var D = class {
  static {
    __name(this, "D");
  }
  Deserialize(e) {
    let r = l.sidFromCryoBuffer(e), s = e.readUInt32BE(16), t = e.readUInt8(20), a = e.subarray(21).toString("utf8");
    if (t !== 7) throw new Error("Attempt to deserialize a non-handshake_done message!");
    return { sid: r, ack: s, type: t, payload: a };
  }
  Serialize(e, r, s) {
    let t = c.alloc(21 + (s?.length || 4));
    return l.sidToCryoBuffer(e).copy(t, 0), t.writeUInt32BE(r, 16), t.writeUInt8(7, 20), t.write(s || "null", 21), t;
  }
};
var o = class {
  static {
    __name(this, "o");
  }
  static GetFormatter(e) {
    switch (e) {
      case "utf8data":
      case 3:
        return new v();
      case "error":
      case 1:
        return new M();
      case "ack":
      case 0:
        return new w();
      case "ping_pong":
      case 2:
        return new A();
      case "binarydata":
      case 4:
        return new T();
      case 5:
      case "server_hello":
        return new S();
      case 6:
      case "client_hello":
        return new U();
      case 7:
      case "handshake_done":
        return new D();
      default:
        throw new Error(`Binary message format for type '${e}' is not supported!`);
    }
  }
  static GetType(e) {
    let r = e.readUInt8(20);
    if (r > 7) throw new Error(`Unable to decode type from message ${e}. MAX_TYPE = 7, got ${r} !`);
    return r;
  }
  static GetAck(e) {
    return e.readUInt32BE(16);
  }
  static GetSid(e) {
    return l.sidFromCryoBuffer(e);
  }
  static GetPayload(e, r) {
    return e.subarray(21).toString(r);
  }
};
var H = { 0: "ack", 1: "error", 2: "ping/pong", 3: "utf8data", 4: "binarydata", 5: "server_hello", 6: "client_hello", 7: "handshake_done" };
var _ = class {
  static {
    __name(this, "_");
  }
  static Inspect(e, r = "utf8") {
    let s = o.GetSid(e), t = o.GetAck(e), a = o.GetType(e), i = H[a] || "unknown", y = o.GetPayload(e, r);
    return `[${s},${t},${i},[${y}]]`;
  }
};
function b(n5) {
  return localStorage.getItem("CRYO_DEBUG")?.includes(n5) ? (e, ...r) => {
    let i = (new Error().stack?.split(`
`)?.[2] ?? "unknown").trim().replace(/^at\s+/, ""), y = i.substring(0, i.indexOf("(") - 1), f = i.substring(i.lastIndexOf(":") - 2, i.length - 1);
    console.info(`${n5.padEnd(24, " ")}${(/* @__PURE__ */ new Date()).toISOString().padEnd(32, " ")} ${y.padEnd(64, " ")} ${f.padEnd(8, " ")} ${e}`, ...r);
  } : () => {
  };
}
__name(b, "b");
var E = class {
  static {
    __name(this, "E");
  }
  target = new EventTarget();
  on(e, r) {
    p.CastAs(e), this.target.addEventListener(e, (s) => {
      r(s.detail);
    });
  }
  emit(e, r) {
    p.CastAs(e), this.target.dispatchEvent(new CustomEvent(e, { detail: r }));
  }
};
async function F(n5, e) {
  return crypto.subtle.importKey("raw", n5.buffer, { name: "AES-GCM" }, false, e);
}
__name(F, "F");
function L(n5) {
  return { name: "AES-GCM", iv: n5.buffer };
}
__name(L, "L");
var B = class {
  static {
    __name(this, "B");
  }
  nonce = 0;
  enc_key_promise;
  dec_key_promise;
  constructor(e, r) {
    this.enc_key_promise = F(e, ["encrypt"]), this.dec_key_promise = F(r, ["decrypt"]);
  }
  create_iv() {
    let e = c.alloc(12);
    return e.writeUInt32BE(this.nonce++, 8), e;
  }
  async encrypt(e) {
    let r = this.create_iv(), s = await this.enc_key_promise, t = await crypto.subtle.encrypt(L(r), s, e.buffer);
    return c.concat([r, new c(new Uint8Array(t))]);
  }
  async decrypt(e) {
    let r = e.subarray(0, 12), s = await this.dec_key_promise, t = e.subarray(12), a = await crypto.subtle.decrypt(L(r), s, t.buffer);
    return new c(new Uint8Array(a));
  }
};
var C = class {
  static {
    __name(this, "C");
  }
  constructor(e, r, s, t, a) {
    this.sid = e;
    this.send_plain = r;
    this.formatter = s;
    this.next_ack = t;
    this.events = a;
  }
  ECDH_ALGO = { name: "ECDH", namedCurve: "P-256" };
  handshake_state = 0;
  ecdh = null;
  receive_key = null;
  transmit_key = null;
  async init_keys() {
    try {
      this.ecdh = await crypto.subtle.generateKey(this.ECDH_ALGO, true, ["deriveBits"]), this.handshake_state = 1;
    } catch (e) {
      this.events.onFailure(`Failed to generate ECDH keys: ${e}`);
    }
  }
  async on_server_hello(e) {
    if (this.ecdh || await this.init_keys(), this.handshake_state !== 1) {
      this.events.onFailure(`CLIENT_HELLO received while in state ${this.handshake_state}`);
      return;
    }
    let r = o.GetFormatter("server_hello").Deserialize(e), s = await crypto.subtle.importKey("raw", r.payload.buffer, this.ECDH_ALGO, false, []);
    if (!this.ecdh?.privateKey) {
      this.events.onFailure("Local ECDH private key not initialised.");
      return;
    }
    let t = await crypto.subtle.deriveBits({ name: "ECDH", public: s }, this.ecdh.privateKey, 256), a = new Uint8Array(await crypto.subtle.digest("SHA-256", t));
    this.transmit_key = new c(a.subarray(16, 32)), this.receive_key = new c(a.subarray(0, 16));
    let i = new c(new Uint8Array(await crypto.subtle.exportKey("raw", this.ecdh.publicKey))), y = this.next_ack(), f = this.formatter.GetFormatter("client_hello").Serialize(this.sid, y, i);
    await this.send_plain(f), this.handshake_state = 2;
  }
  async on_server_handshake_done(e) {
    if (this.handshake_state !== 2) {
      this.events.onFailure(`HANDSHAKE_DONE received while in state ${this.state}`);
      return;
    }
    let r = o.GetFormatter("handshake_done").Deserialize(e), s = o.GetFormatter("handshake_done").Serialize(this.sid, r.ack, null);
    await this.send_plain(s), this.events.onSecure({ receive_key: this.receive_key, transmit_key: this.transmit_key }), this.handshake_state = 3;
  }
  get is_secure() {
    return this.handshake_state === 3;
  }
  get state() {
    return this.handshake_state;
  }
};
var m = class {
  static {
    __name(this, "m");
  }
  constructor(e, r, s, t, a = b("CRYO_FRAME_ROUTER")) {
    this.formatter = e;
    this.is_secure = r;
    this.decrypt = s;
    this.handlers = t;
    this.log = a;
  }
  try_get_type(e) {
    try {
      return o.GetType(e);
    } catch {
      return null;
    }
  }
  async do_route(e) {
    let r = e, s = this.try_get_type(e);
    if (s === null && this.is_secure()) try {
      r = await this.decrypt(e), s = this.try_get_type(r);
    } catch (t) {
      this.log(`Decryption failed: ${t}`, e);
      return;
    }
    if (s === null) {
      this.log("Unknown frame type", e);
      return;
    }
    switch (s) {
      case 2:
        await this.handlers.on_ping_pong(r);
        return;
      case 1:
        await this.handlers.on_error(r);
        return;
      case 0:
        await this.handlers.on_ack(r);
        return;
      case 3:
        await this.handlers.on_utf8(r);
        return;
      case 4:
        await this.handlers.on_binary(r);
        return;
      case 5:
        await this.handlers.on_server_hello?.(r);
        return;
      case 6:
        await this.handlers.on_client_hello?.(r);
        return;
      case 7:
        await this.handlers.on_handshake_done?.(r);
        return;
      default:
        this.log(`Unsupported binary message type ${s}!`);
    }
  }
};
function O(n5, e, r) {
  let s = /* @__PURE__ */ __name((t) => {
    n5.removeEventListener(e, s), r(t);
  }, "s");
  n5.addEventListener(e, s);
}
__name(O, "O");
var k = class n4 extends E {
  static {
    __name(this, "n");
  }
  constructor(r, s, t, a, i, y, f = b("CRYO_CLIENT_SESSION")) {
    super();
    this.host = r;
    this.sid = s;
    this.socket = t;
    this.timeout = a;
    this.bearer = i;
    this.use_cale = y;
    this.log = f;
    if (y) {
      let d = { onSecure: /* @__PURE__ */ __name(({ transmit_key: u, receive_key: I }) => {
        this.crypto = new B(u, I), this.log("Channel secured."), this.emit("connected", void 0);
      }, "onSecure"), onFailure: /* @__PURE__ */ __name((u) => {
        this.log(`Handshake failure: ${u}`), this.Destroy(4011, "Failure during CALE handshake.");
      }, "onFailure") };
      this.handshake = new C(this.sid, async (u) => this.socket.send(u.buffer), o, () => this.current_ack++, d), this.router = new m(o, () => this.handshake.is_secure, async (u) => this.crypto.decrypt(u), { on_ping_pong: /* @__PURE__ */ __name(async (u) => this.HandlePingPongMessage(u), "on_ping_pong"), on_ack: /* @__PURE__ */ __name(async (u) => this.HandleAckMessage(u), "on_ack"), on_error: /* @__PURE__ */ __name(async (u) => this.HandleErrorMessage(u), "on_error"), on_utf8: /* @__PURE__ */ __name(async (u) => this.HandleUTF8DataMessage(u), "on_utf8"), on_binary: /* @__PURE__ */ __name(async (u) => this.HandleBinaryDataMessage(u), "on_binary"), on_server_hello: /* @__PURE__ */ __name(async (u) => this.handshake.on_server_hello(u), "on_server_hello"), on_handshake_done: /* @__PURE__ */ __name(async (u) => this.handshake.on_server_handshake_done(u), "on_handshake_done") });
    } else this.log("CALE disabled, running in unencrypted mode."), this.router = new m(o, () => false, async (d) => d, { on_ping_pong: /* @__PURE__ */ __name(async (d) => this.HandlePingPongMessage(d), "on_ping_pong"), on_ack: /* @__PURE__ */ __name(async (d) => this.HandleAckMessage(d), "on_ack"), on_error: /* @__PURE__ */ __name(async (d) => this.HandleErrorMessage(d), "on_error"), on_utf8: /* @__PURE__ */ __name(async (d) => this.HandleUTF8DataMessage(d), "on_utf8"), on_binary: /* @__PURE__ */ __name(async (d) => this.HandleBinaryDataMessage(d), "on_binary"), on_server_hello: /* @__PURE__ */ __name(async (d) => this.Destroy(4010, "CALE Mismatch. The server excepts CALE encryption, which is currently disabled."), "on_server_hello") }), setTimeout(() => this.emit("connected", void 0));
    this.AttachListenersToSocket(t);
  }
  messages_pending_server_ack = /* @__PURE__ */ new Map();
  server_ack_tracker = new h();
  current_ack = 0;
  ping_pong_formatter = o.GetFormatter("ping_pong");
  ack_formatter = o.GetFormatter("ack");
  error_formatter = o.GetFormatter("error");
  utf8_formatter = o.GetFormatter("utf8data");
  binary_formatter = o.GetFormatter("binarydata");
  crypto = null;
  handshake = null;
  router;
  AttachListenersToSocket(r) {
    this.use_cale ? O(r, "message", (s) => {
      if (!(s.data instanceof ArrayBuffer)) return;
      let t = new c(new Uint8Array(s.data)), a = o.GetType(t);
      if (a !== 5) {
        this.log(`CALE mismatch: expected SERVER_HELLO, got ${a}`), this.Destroy(4010, "CALE mismatch: The server has disabled CALE.");
        return;
      }
      this.router.do_route(t).then(() => {
        r.addEventListener("message", async (i) => {
          i.data instanceof ArrayBuffer && await this.router.do_route(new c(new Uint8Array(i.data)));
        });
      });
    }) : r.addEventListener("message", async (s) => {
      s.data instanceof ArrayBuffer && await this.router.do_route(new c(new Uint8Array(s.data)));
    }), r.addEventListener("error", async (s) => {
      await this.HandleError(new Error("Unspecified WebSocket error!", { cause: s }));
    }), r.addEventListener("close", async (s) => {
      await this.HandleClose(s.code, new c(new TextEncoder().encode(s.reason)));
    });
  }
  static async ConstructSocket(r, s, t, a) {
    let i = new URL(r);
    i.searchParams.set("authorization", `Bearer ${t}`), i.searchParams.set("x-cryo-sid", a);
    let y = new WebSocket(i);
    return y.binaryType = "arraybuffer", new Promise((f, d) => {
      setTimeout(() => {
        y.readyState !== WebSocket.OPEN && d(new Error(`Connection timeout of ${s} ms reached!`));
      }, s), y.addEventListener("open", () => {
        f(y);
      }), y.addEventListener("error", (u) => {
        d(new Error("Error during session initialisation!", { cause: u }));
      });
    });
  }
  static async Connect(r, s, t = true, a = 5e3) {
    let i = crypto.randomUUID(), y = await n4.ConstructSocket(r, a, s, i);
    return new n4(r, i, y, a, s, t);
  }
  async HandleOutgoingBinaryMessage(r) {
    if (this.socket.readyState === WebSocket.CLOSING || this.socket.readyState === WebSocket.CLOSED) return;
    let s = o.GetType(r);
    if (s === 3 || s === 4) {
      let a = o.GetAck(r);
      this.server_ack_tracker.Track(a, { timestamp: Date.now(), message: r });
    }
    if (!this.socket) return;
    let t = r;
    this.use_cale && this.secure && (t = await this.crypto.encrypt(r));
    try {
      this.socket.send(t.buffer);
    } catch (a) {
      a instanceof Error && this.HandleError(a).then((i) => null);
    }
    this.log(`Sent ${_.Inspect(r)} to server.`);
  }
  async HandlePingPongMessage(r) {
    let s = this.ping_pong_formatter.Deserialize(r), t = this.ping_pong_formatter.Serialize(this.sid, s.ack, s.payload === "pong" ? "ping" : "pong");
    await this.HandleOutgoingBinaryMessage(t);
  }
  async HandleErrorMessage(r) {
    let s = this.error_formatter.Deserialize(r);
    this.log(s.payload);
  }
  async HandleAckMessage(r) {
    let t = this.ack_formatter.Deserialize(r).ack;
    if (!this.server_ack_tracker.Confirm(t)) {
      this.log(`Got unknown ack_id ${t} from server.`);
      return;
    }
    this.messages_pending_server_ack.delete(t), this.log(`Got ACK ${t} from server.`);
  }
  async HandleUTF8DataMessage(r) {
    let s = this.utf8_formatter.Deserialize(r), t = s.payload, a = this.ack_formatter.Serialize(this.sid, s.ack);
    await this.HandleOutgoingBinaryMessage(a), this.emit("message-utf8", t);
  }
  async HandleBinaryDataMessage(r) {
    let s = this.binary_formatter.Deserialize(r), t = s.payload, a = this.ack_formatter.Serialize(this.sid, s.ack);
    await this.HandleOutgoingBinaryMessage(a), this.emit("message-binary", t);
  }
  async HandleError(r) {
    this.log(`${r.name} Exception in CryoSocket: ${r.message}`), this.socket.close(4002, `CryoSocket ${this.sid} was closed due to an error.`);
  }
  TranslateCloseCode(r) {
    switch (r) {
      case 4e3:
        return "Connection closed normally.";
      case 4001:
        return "Connection closed due to a client error.";
      case 4002:
        return "Connection closed due to a server error.";
      case 4010:
        return "Connection closed due to a mismatch in client/server CALE configuration.";
      case 4011:
        return "Connection closed due to an error in the CALE handshake.";
      default:
        return "Unspecified cause for connection closure.";
    }
  }
  async HandleClose(r, s) {
    if (console.warn(`Websocket was closed. Code=${r} (${this.TranslateCloseCode(r)}), reason=${s.toString("utf8")}.`), r !== 4002) return;
    let t = 0, a = 5e3;
    for (console.error("Abnormal termination of Websocket connection, attempting to reconnect..."), this.socket = null, this.emit("disconnected", void 0); t < 5; ) try {
      this.socket = await n4.ConstructSocket(this.host, this.timeout, this.bearer, this.sid), this.AttachListenersToSocket(this.socket), this.emit("reconnected", void 0);
      return;
    } catch (i) {
      if (i instanceof Error) {
        let y = i.cause?.error?.code;
        console.warn(`Unable to reconnect to '${this.host}'. Error code: '${y}'. Retry attempt in ${a} ms. Attempt ${t++} / 5`), await new Promise((f) => setTimeout(f, a)), a += t * 1e3;
      }
    }
    console.error(`Gave up on reconnecting to '${this.host}'`), this.socket && this.socket.close(), this.emit("closed", [r, s.toString("utf8")]);
  }
  async SendUTF8(r) {
    let s = this.current_ack++, t = o.GetFormatter("utf8data").Serialize(this.sid, s, r);
    await this.HandleOutgoingBinaryMessage(t);
  }
  async SendBinary(r) {
    let s = this.current_ack++, t = o.GetFormatter("binarydata").Serialize(this.sid, s, r);
    await this.HandleOutgoingBinaryMessage(t);
  }
  Close() {
    this.Destroy(4e3, "Client finished.");
  }
  get secure() {
    return this.use_cale && this.crypto !== null;
  }
  get session_id() {
    return this.sid;
  }
  Destroy(r = 1e3, s = "") {
    this.log(`Teardown of session. Code=${r}, reason=${s}`), this.socket.close(r, s);
  }
};
async function he(n5, e, r, s = 5e3) {
  return k.Connect(n5, e, r, s);
}
__name(he, "he");

// src/frontend.ts
document.addEventListener("DOMContentLoaded", async () => {
  const client = await he("ws://localhost:8080", "test", false);
  client.on("connected", () => {
    console.info("Connected to backend.");
  });
  client.on("reconnected", async () => {
    console.info("Reconnected to backend.");
  });
  client.on("disconnected", async () => {
    console.info("Disconnected from backend.");
  });
  client.on("closed", async () => {
    console.info("Backend connection closed.");
  });
  client.on("message-utf8", (message) => {
    const { html, target, events } = JSON.parse(message);
    console.info(`Got UI data from the backend. Rendering '${target}'`);
    const domElement = document.querySelector(`[data-target=${target}]`);
    if (!domElement) {
      throw new Error(`Element with data-target '${target}' not found in DOM!`);
    }
    domElement.outerHTML = html;
    document.querySelectorAll("[data-event]").forEach((element) => {
      const eventTypes = element.getAttribute("data-event");
      const eventTarget = element.getAttribute("data-target");
      if (!eventTypes) {
        console.warn(`Element with data-target '${element.id}' either has no data-event property or it has no value.`);
        return;
      }
      if (!eventTarget) {
        console.warn(`Element with data-target '${element.id}' either has no data-target property or it has no value.`);
        return;
      }
      const events2 = eventTypes.split(",");
      events2.forEach((eventType) => {
        element.addEventListener(eventType, (e) => {
          e.stopImmediatePropagation();
          e.preventDefault();
          let data = {};
          if (e.target instanceof HTMLFormElement)
            data = Object.fromEntries(new FormData(e.target));
          else
            data = Object.fromEntries(Object.entries(element?.dataset || {}));
          delete data?.event;
          delete data?.target;
          client.SendUTF8(JSON.stringify({ type: eventType, target: eventTarget, data }));
          return;
        });
      });
    });
  });
});
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NvbW1vbi9BY2tUcmFja2VyL0Fja1RyYWNrZXIudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NvbW1vbi9DcnlvQnVmZmVyL0NyeW9CdWZmZXIudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NvbW1vbi9VdGlsL0d1YXJkLnRzIiwgIi4uL25vZGVfbW9kdWxlcy9jcnlvLWNsaWVudC1icm93c2VyL3NyYy9Db21tb24vQ3J5b0JpbmFyeU1lc3NhZ2UvQ3J5b0ZyYW1lRm9ybWF0dGVyLnRzIiwgIi4uL25vZGVfbW9kdWxlcy9jcnlvLWNsaWVudC1icm93c2VyL3NyYy9Db21tb24vQ3J5b0ZyYW1lSW5zcGVjdG9yL0NyeW9GcmFtZUluc3BlY3Rvci50cyIsICIuLi9ub2RlX21vZHVsZXMvY3J5by1jbGllbnQtYnJvd3Nlci9zcmMvQ29tbW9uL1V0aWwvQ3JlYXRlRGVidWdMb2dnZXIudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NvbW1vbi9DcnlvRXZlbnRFbWl0dGVyL0NyeW9FdmVudEVtaXR0ZXIudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uL0NyeW9DcnlwdG9Cb3gudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uL0NyeW9IYW5kc2hha2VFbmdpbmUudHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL0NyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uL0NyeW9GcmFtZVJvdXRlci50cyIsICIuLi9ub2RlX21vZHVsZXMvY3J5by1jbGllbnQtYnJvd3Nlci9zcmMvQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24vQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24udHMiLCAiLi4vbm9kZV9tb2R1bGVzL2NyeW8tY2xpZW50LWJyb3dzZXIvc3JjL2luZGV4LnRzIiwgIi4uL3NyYy9mcm9udGVuZC50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHtDcnlvQnVmZmVyfSBmcm9tIFwiLi4vQ3J5b0J1ZmZlci9DcnlvQnVmZmVyLmpzXCI7XG5cbnR5cGUgUGVuZGluZ0JpbmFyeU1lc3NhZ2UgPSB7XG4gICAgdGltZXN0YW1wOiBudW1iZXI7XG4gICAgbWVzc2FnZTogQ3J5b0J1ZmZlcjtcbiAgICBwYXlsb2FkPzogc3RyaW5nIHwgQ3J5b0J1ZmZlcjtcbn1cblxuZXhwb3J0IGNsYXNzIEFja1RyYWNrZXIge1xuICAgIHByaXZhdGUgcGVuZGluZyA9IG5ldyBNYXA8bnVtYmVyLCBQZW5kaW5nQmluYXJ5TWVzc2FnZT4oKTtcblxuICAgIHB1YmxpYyBUcmFjayhhY2s6IG51bWJlciwgbWVzc2FnZTogUGVuZGluZ0JpbmFyeU1lc3NhZ2UpIHtcbiAgICAgICAgdGhpcy5wZW5kaW5nLnNldChhY2ssIG1lc3NhZ2UpO1xuICAgIH1cblxuICAgIHB1YmxpYyBDb25maXJtKGFjazogbnVtYmVyKTogUGVuZGluZ0JpbmFyeU1lc3NhZ2UgfCBudWxsIHtcbiAgICAgICAgY29uc3QgbWF5YmVfYWNrID0gdGhpcy5wZW5kaW5nLmdldChhY2spO1xuICAgICAgICBpZiAoIW1heWJlX2FjaylcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuXG4gICAgICAgIHRoaXMucGVuZGluZy5kZWxldGUoYWNrKTtcbiAgICAgICAgcmV0dXJuIG1heWJlX2FjaztcbiAgICB9XG5cbiAgICBwdWJsaWMgSGFzKGFjazogbnVtYmVyKTogYm9vbGVhbiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBlbmRpbmcuaGFzKGFjayk7XG4gICAgfVxufVxuIiwgImV4cG9ydCBjbGFzcyBDcnlvQnVmZmVyIHtcbiAgICBwcml2YXRlIHZpZXc6IERhdGFWaWV3O1xuXG4gICAgcHVibGljIGNvbnN0cnVjdG9yKHB1YmxpYyBidWZmZXI6IFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgdGhpcy52aWV3ID0gbmV3IERhdGFWaWV3KGJ1ZmZlci5idWZmZXIsIGJ1ZmZlci5ieXRlT2Zmc2V0LCBidWZmZXIuYnl0ZUxlbmd0aCk7XG4gICAgfVxuXG4gICAgcHVibGljIHN0YXRpYyBhbGxvYyhsZW5ndGg6IG51bWJlcik6IENyeW9CdWZmZXIge1xuICAgICAgICByZXR1cm4gbmV3IENyeW9CdWZmZXIobmV3IFVpbnQ4QXJyYXkobGVuZ3RoKSk7XG4gICAgfVxuXG4gICAgcHVibGljIHN0YXRpYyBmcm9tKGlucHV0OiBzdHJpbmcsIGVuY29kaW5nPzogXCJ1dGY4XCIgfCBcImhleFwiKTogQ3J5b0J1ZmZlciB7XG4gICAgICAgIGlmIChlbmNvZGluZyA9PT0gXCJ1dGY4XCIpXG4gICAgICAgICAgICByZXR1cm4gbmV3IENyeW9CdWZmZXIobmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKGlucHV0KSk7XG5cbiAgICAgICAgY29uc3QgZGF0YSA9IG5ldyBVaW50OEFycmF5KGlucHV0Lmxlbmd0aCAvIDIpO1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGRhdGEubGVuZ3RoOyBpKyspXG4gICAgICAgICAgICBkYXRhW2ldID0gcGFyc2VJbnQoaW5wdXQuc3Vic3RyaW5nKGkgKiAyLCBpICogMiArIDIpLCAxNik7XG5cbiAgICAgICAgcmV0dXJuIG5ldyBDcnlvQnVmZmVyKGRhdGEpO1xuICAgIH1cblxuICAgIHB1YmxpYyBzdGF0aWMgY29uY2F0KGJ1ZmZlcnM6IENyeW9CdWZmZXJbXSk6IENyeW9CdWZmZXIge1xuICAgICAgICBpZiAoYnVmZmVycy5sZW5ndGggPT09IDApXG4gICAgICAgICAgICByZXR1cm4gQ3J5b0J1ZmZlci5hbGxvYygwKTtcblxuICAgICAgICBjb25zdCBsZW5ndGhfdG90YWwgPSBidWZmZXJzLnJlZHVjZSgoYWNjLCB2KSA9PiBhY2MgKyB2Lmxlbmd0aCwgMClcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gbmV3IFVpbnQ4QXJyYXkobGVuZ3RoX3RvdGFsKTtcblxuICAgICAgICBsZXQgb2Zmc2V0ID0gMDtcbiAgICAgICAgZm9yIChjb25zdCBidWYgb2YgYnVmZmVycykge1xuICAgICAgICAgICAgcmVzdWx0LnNldChidWYuYnVmZmVyLCBvZmZzZXQpO1xuICAgICAgICAgICAgb2Zmc2V0ICs9IGJ1Zi5sZW5ndGg7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IENyeW9CdWZmZXIocmVzdWx0KTtcbiAgICB9XG5cblxuICAgIHB1YmxpYyB3cml0ZVVJbnQzMkJFKHZhbHVlOiBudW1iZXIsIG9mZnNldDogbnVtYmVyKTogdm9pZCB7XG4gICAgICAgIHRoaXMudmlldy5zZXRVaW50MzIob2Zmc2V0LCB2YWx1ZSk7XG4gICAgfVxuXG4gICAgcHVibGljIHdyaXRlVUludDgodmFsdWU6IG51bWJlciwgb2Zmc2V0OiBudW1iZXIpOiB2b2lkIHtcbiAgICAgICAgdGhpcy52aWV3LnNldFVpbnQ4KG9mZnNldCwgdmFsdWUpO1xuICAgIH1cblxuICAgIHB1YmxpYyByZWFkVUludDMyQkUob2Zmc2V0OiBudW1iZXIpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gdGhpcy52aWV3LmdldFVpbnQzMihvZmZzZXQpO1xuICAgIH1cblxuICAgIHB1YmxpYyByZWFkVUludDgob2Zmc2V0OiBudW1iZXIpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gdGhpcy52aWV3LmdldFVpbnQ4KG9mZnNldCk7XG4gICAgfVxuXG4gICAgcHVibGljIHdyaXRlKHRleHQ6IHN0cmluZywgb2Zmc2V0OiBudW1iZXIgPSAwKTogdm9pZCB7XG4gICAgICAgIHRoaXMuYnVmZmVyLnNldChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCksIG9mZnNldCk7XG4gICAgfVxuXG4gICAgcHVibGljIHNldChidWZmZXI6IENyeW9CdWZmZXIsIG9mZnNldDogbnVtYmVyKTogdm9pZCB7XG4gICAgICAgIHRoaXMuYnVmZmVyLnNldChidWZmZXIuYnVmZmVyLCBvZmZzZXQpO1xuICAgIH1cblxuICAgIHB1YmxpYyB0b1N0cmluZyhlbmNvZGluZzogXCJ1dGY4XCIgfCBcImhleFwiKTogc3RyaW5nIHtcbiAgICAgICAgaWYgKGVuY29kaW5nID09PSBcInV0ZjhcIilcbiAgICAgICAgICAgIHJldHVybiBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUodGhpcy5idWZmZXIpO1xuXG4gICAgICAgIHJldHVybiBbLi4udGhpcy5idWZmZXJdXG4gICAgICAgICAgICAubWFwKGJ5dGUgPT4gYnl0ZS50b1N0cmluZygxNikucGFkU3RhcnQoMiwgXCIwXCIpKVxuICAgICAgICAgICAgLmpvaW4oXCJcIik7XG4gICAgfVxuXG4gICAgcHVibGljIHN1YmFycmF5KHN0YXJ0OiBudW1iZXIsIGVuZD86IG51bWJlcik6IENyeW9CdWZmZXIge1xuICAgICAgICByZXR1cm4gbmV3IENyeW9CdWZmZXIodGhpcy5idWZmZXIuc3ViYXJyYXkoc3RhcnQsIGVuZCkpO1xuICAgIH1cblxuICAgIHB1YmxpYyBjb3B5KHRhcmdldDogQ3J5b0J1ZmZlciwgdGFyZ2V0X3N0YXJ0ID0gMCk6IHZvaWQge1xuICAgICAgICB0YXJnZXQuYnVmZmVyLnNldCh0aGlzLmJ1ZmZlciwgdGFyZ2V0X3N0YXJ0KTtcbiAgICB9XG5cbiAgICBwdWJsaWMgZ2V0IGxlbmd0aCgpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gdGhpcy5idWZmZXIuYnl0ZUxlbmd0aDtcbiAgICB9XG59XG4iLCAiY2xhc3MgR3VhcmRFcnJvciBleHRlbmRzIEVycm9yIHtcblx0Y29uc3RydWN0b3IocE1lc3NhZ2U6IHN0cmluZykge1xuXHRcdHN1cGVyKHBNZXNzYWdlKTtcblx0XHRPYmplY3Quc2V0UHJvdG90eXBlT2YodGhpcywgR3VhcmRFcnJvci5wcm90b3R5cGUpO1xuXHR9XG59XG5cbi8qXG4qIEhlbGZlcmtsYXNzZSBtaXQgc3RhdGlzY2hlbiBGdW5rdGlvbmVuIHp1bSBcInVuZGVmaW5lZFwiIHVuZCBcIm51bGxcIi1jaGVja2VuLCBpbSBXZXNlbnRsaWNoZW4gZmFuY3kgYXNzZXJ0cyB1bmQgY2FzdHMuXG4qICovXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBHdWFyZCB7XG5cdC8vd2VubiBcInBhcmFtXCIgPT09IG51bGwsIHRocm93IHdpdGggXCJtZXNzYWdlXCJcblx0cHVibGljIHN0YXRpYyBBZ2FpbnN0TnVsbDxUPihwYXJhbTogVCwgbWVzc2FnZT86IHN0cmluZyk6IGFzc2VydHMgcGFyYW0gaXMgRXhjbHVkZTxULCBudWxsPiB7XG5cdFx0aWYgKHBhcmFtID09PSBudWxsKVxuXHRcdFx0dGhyb3cgbmV3IEd1YXJkRXJyb3IobWVzc2FnZSA/IG1lc3NhZ2UgOiBgQXNzZXJ0aW9uIGZhaWxlZCwgXCJwYXJhbVwiICgke3BhcmFtfSkgd2FzIG51bGwhYCk7XG5cdH1cblxuXHQvL1dlbm4gXCJwYXJhbVwiID09PSBcInVuZGVmaW5lZFwiLCB0aHJvdyB3aXRoIFwibWVzc2FnZVwiXG5cdHB1YmxpYyBzdGF0aWMgQWdhaW5zdFVuZGVmaW5lZDxUPihwYXJhbTogVCwgbWVzc2FnZT86IHN0cmluZyk6IGFzc2VydHMgcGFyYW0gaXMgRXhjbHVkZTxULCB1bmRlZmluZWQ+IHtcblx0XHRpZiAocGFyYW0gPT09IHVuZGVmaW5lZClcblx0XHRcdHRocm93IG5ldyBHdWFyZEVycm9yKG1lc3NhZ2UgPyBtZXNzYWdlIDogYEFzc2VydGlvbiBmYWlsZWQsIFwicGFyYW1cIiAoJHtwYXJhbX0pIHdhcyB1bmRlZmluZWQhYCk7XG5cdH1cblxuXHQvL1dlbm4gXCJwYXJhbVwiID09PSBcIm51bGxcIiBvciBcInBhcmFtXCIgPT09IFwidW5kZWZpbmVkXCIsIHRocm93IHdpdGggXCJtZXNzYWdlXCJcblx0cHVibGljIHN0YXRpYyBBZ2FpbnN0TnVsbGlzaDxUPihwYXJhbTogVCwgbWVzc2FnZT86IHN0cmluZyk6IGFzc2VydHMgcGFyYW0gaXMgRXhjbHVkZTxFeGNsdWRlPFQsIG51bGw+LCB1bmRlZmluZWQ+IHtcblx0XHRHdWFyZC5BZ2FpbnN0VW5kZWZpbmVkKHBhcmFtLCBtZXNzYWdlKTtcblx0XHRHdWFyZC5BZ2FpbnN0TnVsbChwYXJhbSwgbWVzc2FnZSk7XG5cdH1cblxuXHQvL1R5cCB2b24gXCJwYXJhbVwiIGFscyBUeXAgXCJUXCIgaW50ZXJwcmV0aWVyZW5cblx0cHVibGljIHN0YXRpYyBDYXN0QXM8VD4ocGFyYW06IHVua25vd24pOiBhc3NlcnRzIHBhcmFtIGlzIFQge1xuXHRcdEd1YXJkLkFnYWluc3ROdWxsaXNoKHBhcmFtKTtcblx0fVxuXG5cdC8vVHlwIHZvbiBcInBhcmFtXCIgYWxzIFR5cCBcIlRcIiBpbnRlcnByZXRpZXJlbiB1bmQgXCJwYXJhbVwiIHVuZCBcImV4cHJcIiBnZWdlbiBcIm51bGxcIiB1bmQgXCJ1bmRlZmluZWRcIiBndWFyZGVuXG5cdHB1YmxpYyBzdGF0aWMgQ2FzdEFzc2VydDxUPihwYXJhbTogdW5rbm93biwgZXhwcjogYm9vbGVhbiwgbWVzc2FnZT86IHN0cmluZyk6IGFzc2VydHMgcGFyYW0gaXMgVCB7XG5cdFx0R3VhcmQuQWdhaW5zdE51bGxpc2gocGFyYW0sIG1lc3NhZ2UpO1xuXHRcdEd1YXJkLkFnYWluc3ROdWxsaXNoKGV4cHIsIG1lc3NhZ2UpO1xuXHRcdGlmKCFleHByKVxuXHRcdFx0dGhyb3cgbmV3IEd1YXJkRXJyb3IoYFBhcmFtZXRlciBhc3NlcnRpb24gZmFpbGVkIGluIENhc3RBc3NlcnQhYCk7XG5cdH1cbn1cbiIsICJpbXBvcnQge0NyeW9CdWZmZXJ9IGZyb20gXCIuLi9DcnlvQnVmZmVyL0NyeW9CdWZmZXIuanNcIjtcbmltcG9ydCBHdWFyZCBmcm9tIFwiLi4vVXRpbC9HdWFyZC5qc1wiO1xuXG50eXBlIFVVSUQgPSBgJHtzdHJpbmd9LSR7c3RyaW5nfS0ke3N0cmluZ30tJHtzdHJpbmd9LSR7c3RyaW5nfWA7XG50eXBlIEJ1ZmZlciA9IENyeW9CdWZmZXI7XG5cblxuZXhwb3J0IGVudW0gQmluYXJ5TWVzc2FnZVR5cGUge1xuICAgIEFDSyA9IDAsXG4gICAgRVJST1IgPSAxLFxuICAgIFBJTkdfUE9ORyA9IDIsXG4gICAgVVRGOERBVEEgPSAzLFxuICAgIEJJTkFSWURBVEEgPSA0LFxuICAgIFNFUlZFUl9IRUxMTyA9IDUsXG4gICAgQ0xJRU5UX0hFTExPID0gNixcbiAgICBIQU5EU0hBS0VfRE9ORSA9IDdcbn1cblxudHlwZSBCaW5hcnlNZXNzYWdlPFQsIFUgZXh0ZW5kcyBCaW5hcnlNZXNzYWdlVHlwZT4gPSB7XG4gICAgc2lkOiBVVUlEO1xuICAgIHR5cGU6IFU7XG59ICYgVDtcblxudHlwZSBBY2tNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG59LCBCaW5hcnlNZXNzYWdlVHlwZS5BQ0s+O1xuXG50eXBlIFBpbmdNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogXCJwaW5nXCIgfCBcInBvbmdcIjtcbn0sIEJpbmFyeU1lc3NhZ2VUeXBlLlBJTkdfUE9ORz47XG5cbnR5cGUgVVRGOERhdGFNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogc3RyaW5nO1xufSwgQmluYXJ5TWVzc2FnZVR5cGUuVVRGOERBVEE+O1xuXG50eXBlIEJpbmFyeURhdGFNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogQnVmZmVyO1xufSwgQmluYXJ5TWVzc2FnZVR5cGUuQklOQVJZREFUQT47XG5cbnR5cGUgRXJyb3JNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogXCJpbnZhbGlkX29wZXJhdGlvblwiIHwgXCJzZXNzaW9uX2V4cGlyZWRcIiB8IFwiZXJyb3JcIjtcbn0sIEJpbmFyeU1lc3NhZ2VUeXBlLkVSUk9SPjtcblxudHlwZSBTZXJ2ZXJIZWxsb01lc3NhZ2UgPSBCaW5hcnlNZXNzYWdlPHtcbiAgICBhY2s6IG51bWJlcjtcbiAgICBwYXlsb2FkOiBCdWZmZXI7XG59LCBCaW5hcnlNZXNzYWdlVHlwZS5TRVJWRVJfSEVMTE8+XG5cbnR5cGUgQ2xpZW50SGVsbG9NZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogQnVmZmVyO1xufSwgQmluYXJ5TWVzc2FnZVR5cGUuQ0xJRU5UX0hFTExPPlxuXG50eXBlIEhhbmRzaGFrZURvbmVNZXNzYWdlID0gQmluYXJ5TWVzc2FnZTx7XG4gICAgYWNrOiBudW1iZXI7XG4gICAgcGF5bG9hZDogc3RyaW5nIHwgbnVsbDtcbn0sIEJpbmFyeU1lc3NhZ2VUeXBlLkhBTkRTSEFLRV9ET05FPlxuXG5cbnR5cGUgQ3J5b0FsbEJpbmFyeU1lc3NhZ2UgPVxuICAgIEFja01lc3NhZ2VcbiAgICB8IFBpbmdNZXNzYWdlXG4gICAgfCBVVEY4RGF0YU1lc3NhZ2VcbiAgICB8IEVycm9yTWVzc2FnZVxuICAgIHwgQmluYXJ5RGF0YU1lc3NhZ2VcbiAgICB8IFNlcnZlckhlbGxvTWVzc2FnZVxuICAgIHwgQ2xpZW50SGVsbG9NZXNzYWdlXG4gICAgfCBIYW5kc2hha2VEb25lTWVzc2FnZTtcblxuaW50ZXJmYWNlIENyeW9CaW5hcnlGcmFtZUZvcm1hdHRlcjxUIGV4dGVuZHMgQ3J5b0FsbEJpbmFyeU1lc3NhZ2U+IHtcbiAgICBEZXNlcmlhbGl6ZSh2YWx1ZTogQnVmZmVyKTogVDtcblxuICAgIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBzdHJpbmcgfCBCdWZmZXIgfCBudWxsKTogQnVmZmVyO1xufVxuXG5jbGFzcyBDcnlvQnVmZmVyVXRpbCB7XG4gICAgcHVibGljIHN0YXRpYyBzaWRGcm9tQ3J5b0J1ZmZlcihidWZmZXI6IEJ1ZmZlcik6IFVVSUQge1xuICAgICAgICBjb25zdCB1dWlkdjRfcDEgPSBidWZmZXIuc3ViYXJyYXkoMCwgNCkudG9TdHJpbmcoXCJoZXhcIik7XG4gICAgICAgIGNvbnN0IHV1aWR2NF9wMiA9IGJ1ZmZlci5zdWJhcnJheSg0LCA2KS50b1N0cmluZyhcImhleFwiKTtcbiAgICAgICAgY29uc3QgdXVpZHY0X3AzID0gYnVmZmVyLnN1YmFycmF5KDYsIDgpLnRvU3RyaW5nKFwiaGV4XCIpO1xuICAgICAgICBjb25zdCB1dWlkdjRfcDQgPSBidWZmZXIuc3ViYXJyYXkoOCwgMTApLnRvU3RyaW5nKFwiaGV4XCIpO1xuICAgICAgICBjb25zdCB1dWlkdjRfcDUgPSBidWZmZXIuc3ViYXJyYXkoMTAsIDE2KS50b1N0cmluZyhcImhleFwiKTtcblxuICAgICAgICByZXR1cm4gW3V1aWR2NF9wMSwgdXVpZHY0X3AyLCB1dWlkdjRfcDMsIHV1aWR2NF9wNCwgdXVpZHY0X3A1XS5qb2luKFwiLVwiKSBhcyBVVUlEO1xuICAgIH1cblxuICAgIHB1YmxpYyBzdGF0aWMgc2lkVG9DcnlvQnVmZmVyKHNpZDogVVVJRCk6IEJ1ZmZlciB7XG4gICAgICAgIHJldHVybiBDcnlvQnVmZmVyLmZyb20oc2lkLnJlcGxhY2VBbGwoXCItXCIsIFwiXCIpLCAnaGV4Jyk7XG4gICAgfVxufVxuXG5jbGFzcyBBY2tGcmFtZUZvcm1hdHRlciBpbXBsZW1lbnRzIENyeW9CaW5hcnlGcmFtZUZvcm1hdHRlcjxBY2tNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBBY2tNZXNzYWdlIHtcbiAgICAgICAgY29uc3Qgc2lkID0gQ3J5b0J1ZmZlclV0aWwuc2lkRnJvbUNyeW9CdWZmZXIodmFsdWUpO1xuICAgICAgICBjb25zdCBhY2sgPSB2YWx1ZS5yZWFkVUludDMyQkUoMTYpO1xuICAgICAgICBjb25zdCB0eXBlID0gdmFsdWUucmVhZFVJbnQ4KDIwKTtcbiAgICAgICAgaWYgKHR5cGUgIT09IEJpbmFyeU1lc3NhZ2VUeXBlLkFDSylcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIkF0dGVtcHQgdG8gZGVzZXJpYWxpemUgYSBub24tYWNrIGJpbmFyeSBtZXNzYWdlIVwiKTtcblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc2lkLFxuICAgICAgICAgICAgYWNrLFxuICAgICAgICAgICAgdHlwZVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgLy8gbm9pbnNwZWN0aW9uIEpTVW51c2VkTG9jYWxTeW1ib2xzXG4gICAgcHVibGljIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBzdHJpbmcgfCBCdWZmZXIgfCBudWxsID0gbnVsbCk6IEJ1ZmZlciB7XG4gICAgICAgIGNvbnN0IG1zZ19idWYgPSBDcnlvQnVmZmVyLmFsbG9jKDE2ICsgNCArIDEpO1xuICAgICAgICBjb25zdCBzaWRfYnVmID0gQ3J5b0J1ZmZlclV0aWwuc2lkVG9DcnlvQnVmZmVyKHNpZCk7XG5cbiAgICAgICAgc2lkX2J1Zi5jb3B5KG1zZ19idWYsIDApO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDMyQkUoYWNrLCAxNik7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50OChCaW5hcnlNZXNzYWdlVHlwZS5BQ0ssIDIwKTtcbiAgICAgICAgcmV0dXJuIG1zZ19idWY7XG4gICAgfVxufVxuXG5jbGFzcyBQaW5nUG9uZ0ZyYW1lRm9ybWF0dGVyIGltcGxlbWVudHMgQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPFBpbmdNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBQaW5nTWVzc2FnZSB7XG4gICAgICAgIGNvbnN0IHNpZCA9IENyeW9CdWZmZXJVdGlsLnNpZEZyb21DcnlvQnVmZmVyKHZhbHVlKTtcbiAgICAgICAgY29uc3QgYWNrID0gdmFsdWUucmVhZFVJbnQzMkJFKDE2KTtcbiAgICAgICAgY29uc3QgdHlwZSA9IHZhbHVlLnJlYWRVSW50OCgyMCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSB2YWx1ZS5zdWJhcnJheSgyMSkudG9TdHJpbmcoXCJ1dGY4XCIpO1xuICAgICAgICBpZiAodHlwZSAhPT0gQmluYXJ5TWVzc2FnZVR5cGUuUElOR19QT05HKVxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQXR0ZW1wdCB0byBkZXNlcmlhbGl6ZSBhIG5vbi1waW5nX3BvbmcgYmluYXJ5IG1lc3NhZ2UhXCIpO1xuXG4gICAgICAgIGlmICghKHBheWxvYWQgPT09IFwicGluZ1wiIHx8IHBheWxvYWQgPT09IFwicG9uZ1wiKSlcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgSW52YWxpZCBwYXlsb2FkICR7cGF5bG9hZH0gaW4gcGluZ19wb25nIGJpbmFyeSBtZXNzYWdlIWApO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBzaWQsXG4gICAgICAgICAgICBhY2ssXG4gICAgICAgICAgICB0eXBlLFxuICAgICAgICAgICAgcGF5bG9hZFxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHVibGljIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBcInBpbmdcIiB8IFwicG9uZ1wiKTogQnVmZmVyIHtcbiAgICAgICAgY29uc3QgbXNnX2J1ZiA9IENyeW9CdWZmZXIuYWxsb2MoMTYgKyA0ICsgMSArIDQpO1xuICAgICAgICBjb25zdCBzaWRfYnVmID0gQ3J5b0J1ZmZlclV0aWwuc2lkVG9DcnlvQnVmZmVyKHNpZCk7XG5cbiAgICAgICAgc2lkX2J1Zi5jb3B5KG1zZ19idWYsIDApO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDMyQkUoYWNrLCAxNik7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50OChCaW5hcnlNZXNzYWdlVHlwZS5QSU5HX1BPTkcsIDIwKTtcbiAgICAgICAgbXNnX2J1Zi53cml0ZShwYXlsb2FkLCAyMSk7XG5cbiAgICAgICAgcmV0dXJuIG1zZ19idWY7XG4gICAgfVxufVxuXG5jbGFzcyBVVEY4RnJhbWVGb3JtYXR0ZXIgaW1wbGVtZW50cyBDcnlvQmluYXJ5RnJhbWVGb3JtYXR0ZXI8VVRGOERhdGFNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBVVEY4RGF0YU1lc3NhZ2Uge1xuICAgICAgICBjb25zdCBzaWQgPSBDcnlvQnVmZmVyVXRpbC5zaWRGcm9tQ3J5b0J1ZmZlcih2YWx1ZSk7XG4gICAgICAgIGNvbnN0IGFjayA9IHZhbHVlLnJlYWRVSW50MzJCRSgxNik7XG4gICAgICAgIGNvbnN0IHR5cGUgPSB2YWx1ZS5yZWFkVUludDgoMjApO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gdmFsdWUuc3ViYXJyYXkoMjEpLnRvU3RyaW5nKFwidXRmOFwiKTtcblxuICAgICAgICBpZiAodHlwZSAhPT0gQmluYXJ5TWVzc2FnZVR5cGUuVVRGOERBVEEpXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJBdHRlbXB0IHRvIGRlc2VyaWFsaXplIGEgbm9uLWRhdGEgYmluYXJ5IG1lc3NhZ2UhXCIpO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBzaWQsXG4gICAgICAgICAgICBhY2ssXG4gICAgICAgICAgICB0eXBlLFxuICAgICAgICAgICAgcGF5bG9hZFxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHVibGljIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBzdHJpbmcgfCBudWxsKTogQnVmZmVyIHtcbiAgICAgICAgY29uc3QgbXNnX2J1ZiA9IENyeW9CdWZmZXIuYWxsb2MoMTYgKyA0ICsgMSArIChwYXlsb2FkPy5sZW5ndGggfHwgNCkpO1xuICAgICAgICBjb25zdCBzaWRfYnVmID0gQ3J5b0J1ZmZlclV0aWwuc2lkVG9DcnlvQnVmZmVyKHNpZCk7XG5cbiAgICAgICAgc2lkX2J1Zi5jb3B5KG1zZ19idWYsIDApO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDMyQkUoYWNrLCAxNik7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50OChCaW5hcnlNZXNzYWdlVHlwZS5VVEY4REFUQSwgMjApO1xuICAgICAgICBtc2dfYnVmLndyaXRlKHBheWxvYWQgfHwgXCJudWxsXCIsIDIxKTtcblxuICAgICAgICByZXR1cm4gbXNnX2J1ZjtcbiAgICB9XG59XG5cbmNsYXNzIEJpbmFyeUZyYW1lRm9ybWF0dGVyIGltcGxlbWVudHMgQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPEJpbmFyeURhdGFNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBCaW5hcnlEYXRhTWVzc2FnZSB7XG4gICAgICAgIGNvbnN0IHNpZCA9IENyeW9CdWZmZXJVdGlsLnNpZEZyb21DcnlvQnVmZmVyKHZhbHVlKTtcbiAgICAgICAgY29uc3QgYWNrID0gdmFsdWUucmVhZFVJbnQzMkJFKDE2KTtcbiAgICAgICAgY29uc3QgdHlwZSA9IHZhbHVlLnJlYWRVSW50OCgyMCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSB2YWx1ZS5zdWJhcnJheSgyMSk7XG5cbiAgICAgICAgaWYgKHR5cGUgIT09IEJpbmFyeU1lc3NhZ2VUeXBlLkJJTkFSWURBVEEpXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJBdHRlbXB0IHRvIGRlc2VyaWFsaXplIGEgbm9uLWRhdGEgYmluYXJ5IG1lc3NhZ2UhXCIpO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBzaWQsXG4gICAgICAgICAgICBhY2ssXG4gICAgICAgICAgICB0eXBlLFxuICAgICAgICAgICAgcGF5bG9hZFxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHVibGljIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBCdWZmZXIgfCBudWxsKTogQnVmZmVyIHtcbiAgICAgICAgY29uc3QgcGF5bG9hZF9sZW5ndGggPSBwYXlsb2FkID8gcGF5bG9hZC5sZW5ndGggOiA0O1xuICAgICAgICBjb25zdCBtc2dfYnVmID0gQ3J5b0J1ZmZlci5hbGxvYygxNiArIDQgKyAxICsgcGF5bG9hZF9sZW5ndGgpO1xuICAgICAgICBjb25zdCBzaWRfYnVmID0gQ3J5b0J1ZmZlclV0aWwuc2lkVG9DcnlvQnVmZmVyKHNpZCk7XG5cbiAgICAgICAgc2lkX2J1Zi5jb3B5KG1zZ19idWYsIDApO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDMyQkUoYWNrLCAxNik7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50OChCaW5hcnlNZXNzYWdlVHlwZS5CSU5BUllEQVRBLCAyMCk7XG4gICAgICAgIG1zZ19idWYuc2V0KHBheWxvYWQgfHwgQ3J5b0J1ZmZlci5mcm9tKFwibnVsbFwiLCBcInV0ZjhcIiksIDIxKTtcblxuICAgICAgICByZXR1cm4gbXNnX2J1ZjtcbiAgICB9XG59XG5cbmNsYXNzIEVycm9yRnJhbWVGb3JtYXR0ZXIgaW1wbGVtZW50cyBDcnlvQmluYXJ5RnJhbWVGb3JtYXR0ZXI8RXJyb3JNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBFcnJvck1lc3NhZ2Uge1xuICAgICAgICBjb25zdCBzaWQgPSBDcnlvQnVmZmVyVXRpbC5zaWRGcm9tQ3J5b0J1ZmZlcih2YWx1ZSk7XG4gICAgICAgIGNvbnN0IGFjayA9IHZhbHVlLnJlYWRVSW50MzJCRSgxNik7XG4gICAgICAgIGNvbnN0IHR5cGUgPSB2YWx1ZS5yZWFkVUludDgoMjApO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gdmFsdWUuc3ViYXJyYXkoMjEpLnRvU3RyaW5nKFwidXRmOFwiKSBhcyBFcnJvck1lc3NhZ2VbXCJwYXlsb2FkXCJdO1xuXG4gICAgICAgIGlmICh0eXBlICE9PSBCaW5hcnlNZXNzYWdlVHlwZS5FUlJPUilcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIkF0dGVtcHQgdG8gZGVzZXJpYWxpemUgYSBub24tZXJyb3IgbWVzc2FnZSFcIik7XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHNpZCxcbiAgICAgICAgICAgIGFjayxcbiAgICAgICAgICAgIHR5cGUsXG4gICAgICAgICAgICBwYXlsb2FkXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwdWJsaWMgU2VyaWFsaXplKHNpZDogVVVJRCwgYWNrOiBudW1iZXIsIHBheWxvYWQ6IEVycm9yTWVzc2FnZVtcInBheWxvYWRcIl0gfCBudWxsKTogQnVmZmVyIHtcbiAgICAgICAgY29uc3QgbXNnX2J1ZiA9IENyeW9CdWZmZXIuYWxsb2MoMTYgKyA0ICsgMSArIChwYXlsb2FkPy5sZW5ndGggfHwgMTMpKTtcbiAgICAgICAgY29uc3Qgc2lkX2J1ZiA9IENyeW9CdWZmZXJVdGlsLnNpZFRvQ3J5b0J1ZmZlcihzaWQpO1xuXG4gICAgICAgIHNpZF9idWYuY29weShtc2dfYnVmLCAwKTtcbiAgICAgICAgbXNnX2J1Zi53cml0ZVVJbnQzMkJFKGFjaywgMTYpO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDgoQmluYXJ5TWVzc2FnZVR5cGUuRVJST1IsIDIwKTtcbiAgICAgICAgbXNnX2J1Zi53cml0ZShwYXlsb2FkIHx8IFwidW5rbm93bl9lcnJvclwiLCAyMSk7XG5cbiAgICAgICAgcmV0dXJuIG1zZ19idWY7XG4gICAgfVxufVxuXG5cbmNsYXNzIFNlcnZlckhlbGxvRnJhbWVGb3JtYXR0ZXIgaW1wbGVtZW50cyBDcnlvQmluYXJ5RnJhbWVGb3JtYXR0ZXI8U2VydmVySGVsbG9NZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBTZXJ2ZXJIZWxsb01lc3NhZ2Uge1xuICAgICAgICBjb25zdCBzaWQgPSBDcnlvQnVmZmVyVXRpbC5zaWRGcm9tQ3J5b0J1ZmZlcih2YWx1ZSk7XG4gICAgICAgIGNvbnN0IGFjayA9IHZhbHVlLnJlYWRVSW50MzJCRSgxNik7XG4gICAgICAgIGNvbnN0IHR5cGUgPSB2YWx1ZS5yZWFkVUludDgoMjApO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gdmFsdWUuc3ViYXJyYXkoMjEpO1xuXG4gICAgICAgIGlmICh0eXBlICE9PSBCaW5hcnlNZXNzYWdlVHlwZS5TRVJWRVJfSEVMTE8pXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJBdHRlbXB0IHRvIGRlc2VyaWFsaXplIGEgbm9uLXNlcnZlcl9oZWxsbyBtZXNzYWdlIVwiKTtcblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc2lkLFxuICAgICAgICAgICAgYWNrLFxuICAgICAgICAgICAgdHlwZSxcbiAgICAgICAgICAgIHBheWxvYWRcbiAgICAgICAgfVxuXG4gICAgfVxuXG4gICAgcHVibGljIFNlcmlhbGl6ZShzaWQ6IFVVSUQsIGFjazogbnVtYmVyLCBwYXlsb2FkOiBCdWZmZXIgfCBudWxsKTogQnVmZmVyIHtcbiAgICAgICAgR3VhcmQuQ2FzdEFzc2VydDxCdWZmZXI+KHBheWxvYWQsIHBheWxvYWQgIT09IG51bGwsIFwicGF5bG9hZCB3YXMgbnVsbCFcIik7XG4gICAgICAgIGlmIChwYXlsb2FkLmxlbmd0aCAhPT0gNjUpXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJQYXlsb2FkIGluIFNlcnZlckhlbGxvTWVzc2FnZSBtdXN0IGJlIGV4YWN0bHkgNjUgYnl0ZXMhXCIpO1xuXG4gICAgICAgIGNvbnN0IG1zZ19idWYgPSBDcnlvQnVmZmVyLmFsbG9jKDE2ICsgNCArIDEgKyA2NSk7XG4gICAgICAgIGNvbnN0IHNpZF9idWYgPSBDcnlvQnVmZmVyVXRpbC5zaWRUb0NyeW9CdWZmZXIoc2lkKTtcblxuICAgICAgICBzaWRfYnVmLmNvcHkobXNnX2J1ZiwgMCk7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50MzJCRShhY2ssIDE2KTtcbiAgICAgICAgbXNnX2J1Zi53cml0ZVVJbnQ4KEJpbmFyeU1lc3NhZ2VUeXBlLlNFUlZFUl9IRUxMTywgMjApO1xuICAgICAgICBtc2dfYnVmLnNldChwYXlsb2FkLCAyMSk7XG5cbiAgICAgICAgcmV0dXJuIG1zZ19idWY7XG4gICAgfVxufVxuXG5jbGFzcyBDbGllbnRIZWxsb0ZyYW1lRm9ybWF0dGVyIGltcGxlbWVudHMgQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPENsaWVudEhlbGxvTWVzc2FnZT4ge1xuICAgIHB1YmxpYyBEZXNlcmlhbGl6ZSh2YWx1ZTogQnVmZmVyKTogQ2xpZW50SGVsbG9NZXNzYWdlIHtcbiAgICAgICAgY29uc3Qgc2lkID0gQ3J5b0J1ZmZlclV0aWwuc2lkRnJvbUNyeW9CdWZmZXIodmFsdWUpO1xuICAgICAgICBjb25zdCBhY2sgPSB2YWx1ZS5yZWFkVUludDMyQkUoMTYpO1xuICAgICAgICBjb25zdCB0eXBlID0gdmFsdWUucmVhZFVJbnQ4KDIwKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHZhbHVlLnN1YmFycmF5KDIxKTtcblxuICAgICAgICBpZiAodHlwZSAhPT0gQmluYXJ5TWVzc2FnZVR5cGUuQ0xJRU5UX0hFTExPKVxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQXR0ZW1wdCB0byBkZXNlcmlhbGl6ZSBhIG5vbi1jbGllbnRfaGVsbG8gbWVzc2FnZSFcIik7XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHNpZCxcbiAgICAgICAgICAgIGFjayxcbiAgICAgICAgICAgIHR5cGUsXG4gICAgICAgICAgICBwYXlsb2FkXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIHB1YmxpYyBTZXJpYWxpemUoc2lkOiBVVUlELCBhY2s6IG51bWJlciwgcGF5bG9hZDogQnVmZmVyIHwgbnVsbCk6IEJ1ZmZlciB7XG4gICAgICAgIEd1YXJkLkNhc3RBc3NlcnQ8QnVmZmVyPihwYXlsb2FkLCBwYXlsb2FkICE9PSBudWxsLCBcInBheWxvYWQgd2FzIG51bGwhXCIpO1xuICAgICAgICBpZiAocGF5bG9hZC5sZW5ndGggIT09IDY1KVxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiUGF5bG9hZCBpbiBDbGllbnRIZWxsb01lc3NhZ2UgbXVzdCBiZSBleGFjdGx5IDY1IGJ5dGVzIVwiKTtcblxuICAgICAgICBjb25zdCBtc2dfYnVmID0gQ3J5b0J1ZmZlci5hbGxvYygxNiArIDQgKyAxICsgNjUpO1xuICAgICAgICBjb25zdCBzaWRfYnVmID0gQ3J5b0J1ZmZlclV0aWwuc2lkVG9DcnlvQnVmZmVyKHNpZCk7XG5cbiAgICAgICAgc2lkX2J1Zi5jb3B5KG1zZ19idWYsIDApO1xuICAgICAgICBtc2dfYnVmLndyaXRlVUludDMyQkUoYWNrLCAxNik7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50OChCaW5hcnlNZXNzYWdlVHlwZS5DTElFTlRfSEVMTE8sIDIwKTtcbiAgICAgICAgbXNnX2J1Zi5zZXQocGF5bG9hZCwgMjEpO1xuXG4gICAgICAgIHJldHVybiBtc2dfYnVmO1xuICAgIH1cbn1cblxuY2xhc3MgSGFuZHNoYWtlRG9uZUZyYW1lRm9ybWF0dGVyIGltcGxlbWVudHMgQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPEhhbmRzaGFrZURvbmVNZXNzYWdlPiB7XG4gICAgcHVibGljIERlc2VyaWFsaXplKHZhbHVlOiBCdWZmZXIpOiBIYW5kc2hha2VEb25lTWVzc2FnZSB7XG4gICAgICAgIGNvbnN0IHNpZCA9IENyeW9CdWZmZXJVdGlsLnNpZEZyb21DcnlvQnVmZmVyKHZhbHVlKTtcbiAgICAgICAgY29uc3QgYWNrID0gdmFsdWUucmVhZFVJbnQzMkJFKDE2KTtcbiAgICAgICAgY29uc3QgdHlwZSA9IHZhbHVlLnJlYWRVSW50OCgyMCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSB2YWx1ZS5zdWJhcnJheSgyMSkudG9TdHJpbmcoXCJ1dGY4XCIpO1xuXG4gICAgICAgIGlmICh0eXBlICE9PSBCaW5hcnlNZXNzYWdlVHlwZS5IQU5EU0hBS0VfRE9ORSlcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIkF0dGVtcHQgdG8gZGVzZXJpYWxpemUgYSBub24taGFuZHNoYWtlX2RvbmUgbWVzc2FnZSFcIik7XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHNpZCxcbiAgICAgICAgICAgIGFjayxcbiAgICAgICAgICAgIHR5cGUsXG4gICAgICAgICAgICBwYXlsb2FkXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwdWJsaWMgU2VyaWFsaXplKHNpZDogVVVJRCwgYWNrOiBudW1iZXIsIHBheWxvYWQ6IHN0cmluZyB8IG51bGwpOiBCdWZmZXIge1xuICAgICAgICBjb25zdCBtc2dfYnVmID0gQ3J5b0J1ZmZlci5hbGxvYygxNiArIDQgKyAxICsgKHBheWxvYWQ/Lmxlbmd0aCB8fCA0KSk7XG4gICAgICAgIGNvbnN0IHNpZF9idWYgPSBDcnlvQnVmZmVyVXRpbC5zaWRUb0NyeW9CdWZmZXIoc2lkKTtcblxuICAgICAgICBzaWRfYnVmLmNvcHkobXNnX2J1ZiwgMCk7XG4gICAgICAgIG1zZ19idWYud3JpdGVVSW50MzJCRShhY2ssIDE2KTtcbiAgICAgICAgbXNnX2J1Zi53cml0ZVVJbnQ4KEJpbmFyeU1lc3NhZ2VUeXBlLkhBTkRTSEFLRV9ET05FLCAyMCk7XG4gICAgICAgIG1zZ19idWYud3JpdGUocGF5bG9hZCB8fCBcIm51bGxcIiwgMjEpO1xuXG4gICAgICAgIHJldHVybiBtc2dfYnVmO1xuICAgIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgQ3J5b0ZyYW1lRm9ybWF0dGVyIHtcbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBcInV0ZjhkYXRhXCIpOiBVVEY4RnJhbWVGb3JtYXR0ZXI7XG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTogQmluYXJ5TWVzc2FnZVR5cGUuVVRGOERBVEEpOiBVVEY4RnJhbWVGb3JtYXR0ZXI7XG5cbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBcInBpbmdfcG9uZ1wiKTogUGluZ1BvbmdGcmFtZUZvcm1hdHRlcjtcbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBCaW5hcnlNZXNzYWdlVHlwZS5QSU5HX1BPTkcpOiBQaW5nUG9uZ0ZyYW1lRm9ybWF0dGVyO1xuXG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTogXCJhY2tcIik6IEFja0ZyYW1lRm9ybWF0dGVyO1xuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IEJpbmFyeU1lc3NhZ2VUeXBlLkFDSyk6IEFja0ZyYW1lRm9ybWF0dGVyO1xuXG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTogXCJlcnJvclwiKTogRXJyb3JGcmFtZUZvcm1hdHRlcjtcbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBCaW5hcnlNZXNzYWdlVHlwZS5FUlJPUik6IEVycm9yRnJhbWVGb3JtYXR0ZXI7XG5cbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBcImJpbmFyeWRhdGFcIik6IEJpbmFyeUZyYW1lRm9ybWF0dGVyO1xuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IEJpbmFyeU1lc3NhZ2VUeXBlLkJJTkFSWURBVEEpOiBCaW5hcnlGcmFtZUZvcm1hdHRlcjtcblxuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IFwic2VydmVyX2hlbGxvXCIpOiBTZXJ2ZXJIZWxsb0ZyYW1lRm9ybWF0dGVyO1xuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IEJpbmFyeU1lc3NhZ2VUeXBlLlNFUlZFUl9IRUxMTyk6IFNlcnZlckhlbGxvRnJhbWVGb3JtYXR0ZXI7XG5cbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBcImNsaWVudF9oZWxsb1wiKTogQ2xpZW50SGVsbG9GcmFtZUZvcm1hdHRlcjtcbiAgICBwdWJsaWMgc3RhdGljIEdldEZvcm1hdHRlcih0eXBlOiBCaW5hcnlNZXNzYWdlVHlwZS5DTElFTlRfSEVMTE8pOiBDbGllbnRIZWxsb0ZyYW1lRm9ybWF0dGVyO1xuXG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTogXCJoYW5kc2hha2VfZG9uZVwiKTogSGFuZHNoYWtlRG9uZUZyYW1lRm9ybWF0dGVyO1xuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IEJpbmFyeU1lc3NhZ2VUeXBlLkhBTkRTSEFLRV9ET05FKTogSGFuZHNoYWtlRG9uZUZyYW1lRm9ybWF0dGVyO1xuXG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTogXCJ1dGY4ZGF0YVwiIHwgXCJwaW5nX3BvbmdcIiB8IFwiYWNrXCIgfCBcImVycm9yXCIgfCBcImJpbmFyeWRhdGFcIiB8IFwic2VydmVyX2hlbGxvXCIgfCBcImNsaWVudF9oZWxsb1wiIHwgXCJoYW5kc2hha2VfZG9uZVwiKTogQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPGFueT47XG4gICAgcHVibGljIHN0YXRpYyBHZXRGb3JtYXR0ZXIodHlwZTpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQmluYXJ5TWVzc2FnZVR5cGUuVVRGOERBVEEgfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5QSU5HX1BPTkcgfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5BQ0sgfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5FUlJPUiB8XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEJpbmFyeU1lc3NhZ2VUeXBlLkJJTkFSWURBVEEgfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5TRVJWRVJfSEVMTE8gfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5DTElFTlRfSEVMTE8gfFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBCaW5hcnlNZXNzYWdlVHlwZS5IQU5EU0hBS0VfRE9ORSk6IENyeW9CaW5hcnlGcmFtZUZvcm1hdHRlcjxhbnk+O1xuICAgIHB1YmxpYyBzdGF0aWMgR2V0Rm9ybWF0dGVyKHR5cGU6IHN0cmluZyB8IEJpbmFyeU1lc3NhZ2VUeXBlKTogQ3J5b0JpbmFyeUZyYW1lRm9ybWF0dGVyPENyeW9BbGxCaW5hcnlNZXNzYWdlPiB7XG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcInV0ZjhkYXRhXCI6XG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLlVURjhEQVRBOlxuICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVVRGOEZyYW1lRm9ybWF0dGVyKCk7XG4gICAgICAgICAgICBjYXNlIFwiZXJyb3JcIjpcbiAgICAgICAgICAgIGNhc2UgQmluYXJ5TWVzc2FnZVR5cGUuRVJST1I6XG4gICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBFcnJvckZyYW1lRm9ybWF0dGVyKCk7XG4gICAgICAgICAgICBjYXNlIFwiYWNrXCI6XG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkFDSzpcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IEFja0ZyYW1lRm9ybWF0dGVyKCk7XG4gICAgICAgICAgICBjYXNlIFwicGluZ19wb25nXCI6XG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLlBJTkdfUE9ORzpcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFBpbmdQb25nRnJhbWVGb3JtYXR0ZXIoKTtcbiAgICAgICAgICAgIGNhc2UgXCJiaW5hcnlkYXRhXCI6XG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkJJTkFSWURBVEE6XG4gICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBCaW5hcnlGcmFtZUZvcm1hdHRlcigpO1xuICAgICAgICAgICAgY2FzZSBCaW5hcnlNZXNzYWdlVHlwZS5TRVJWRVJfSEVMTE86XG4gICAgICAgICAgICBjYXNlIFwic2VydmVyX2hlbGxvXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBTZXJ2ZXJIZWxsb0ZyYW1lRm9ybWF0dGVyKCk7XG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkNMSUVOVF9IRUxMTzpcbiAgICAgICAgICAgIGNhc2UgXCJjbGllbnRfaGVsbG9cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IENsaWVudEhlbGxvRnJhbWVGb3JtYXR0ZXIoKTtcbiAgICAgICAgICAgIGNhc2UgQmluYXJ5TWVzc2FnZVR5cGUuSEFORFNIQUtFX0RPTkU6XG4gICAgICAgICAgICBjYXNlIFwiaGFuZHNoYWtlX2RvbmVcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IEhhbmRzaGFrZURvbmVGcmFtZUZvcm1hdHRlcigpO1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEJpbmFyeSBtZXNzYWdlIGZvcm1hdCBmb3IgdHlwZSAnJHt0eXBlfScgaXMgbm90IHN1cHBvcnRlZCFgKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHVibGljIHN0YXRpYyBHZXRUeXBlKG1lc3NhZ2U6IEJ1ZmZlcik6IEJpbmFyeU1lc3NhZ2VUeXBlIHtcbiAgICAgICAgY29uc3QgdHlwZSA9IG1lc3NhZ2UucmVhZFVJbnQ4KDIwKTtcbiAgICAgICAgaWYgKHR5cGUgPiBCaW5hcnlNZXNzYWdlVHlwZS5IQU5EU0hBS0VfRE9ORSlcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgVW5hYmxlIHRvIGRlY29kZSB0eXBlIGZyb20gbWVzc2FnZSAke21lc3NhZ2V9LiBNQVhfVFlQRSA9IDcsIGdvdCAke3R5cGV9ICFgKTtcblxuICAgICAgICByZXR1cm4gdHlwZTtcbiAgICB9XG5cbiAgICBwdWJsaWMgc3RhdGljIEdldEFjayhtZXNzYWdlOiBCdWZmZXIpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gbWVzc2FnZS5yZWFkVUludDMyQkUoMTYpO1xuICAgIH1cblxuICAgIHB1YmxpYyBzdGF0aWMgR2V0U2lkKG1lc3NhZ2U6IEJ1ZmZlcik6IFVVSUQge1xuICAgICAgICByZXR1cm4gQ3J5b0J1ZmZlclV0aWwuc2lkRnJvbUNyeW9CdWZmZXIobWVzc2FnZSk7XG4gICAgfVxuXG4gICAgcHVibGljIHN0YXRpYyBHZXRQYXlsb2FkKG1lc3NhZ2U6IEJ1ZmZlciwgZW5jb2Rpbmc6IFwidXRmOFwiIHwgXCJoZXhcIik6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiBtZXNzYWdlLnN1YmFycmF5KDIxKS50b1N0cmluZyhlbmNvZGluZyk7XG4gICAgfVxufVxuIiwgImltcG9ydCBDcnlvRnJhbWVGb3JtYXR0ZXIgZnJvbSBcIi4uL0NyeW9CaW5hcnlNZXNzYWdlL0NyeW9GcmFtZUZvcm1hdHRlci5qc1wiO1xuaW1wb3J0IHtDcnlvQnVmZmVyfSBmcm9tIFwiLi4vQ3J5b0J1ZmZlci9DcnlvQnVmZmVyLmpzXCI7XG5cbmNvbnN0IHR5cGVUb1N0cmluZ01hcCA9IHtcbiAgICAwOiBcImFja1wiLFxuICAgIDE6IFwiZXJyb3JcIixcbiAgICAyOiBcInBpbmcvcG9uZ1wiLFxuICAgIDM6IFwidXRmOGRhdGFcIixcbiAgICA0OiBcImJpbmFyeWRhdGFcIixcbiAgICA1OiBcInNlcnZlcl9oZWxsb1wiLFxuICAgIDY6IFwiY2xpZW50X2hlbGxvXCIsXG4gICAgNzogXCJoYW5kc2hha2VfZG9uZVwiLFxufVxuXG5leHBvcnQgY2xhc3MgQ3J5b0ZyYW1lSW5zcGVjdG9yIHtcbiAgICBwdWJsaWMgc3RhdGljIEluc3BlY3QobWVzc2FnZTogQ3J5b0J1ZmZlciwgZW5jb2Rpbmc6IFwidXRmOFwiIHwgXCJoZXhcIiA9IFwidXRmOFwiKTogc3RyaW5nIHtcbiAgICAgICAgY29uc3Qgc2lkID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldFNpZChtZXNzYWdlKTtcbiAgICAgICAgY29uc3QgYWNrID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldEFjayhtZXNzYWdlKTtcbiAgICAgICAgY29uc3QgdHlwZSA9IENyeW9GcmFtZUZvcm1hdHRlci5HZXRUeXBlKG1lc3NhZ2UpO1xuICAgICAgICBjb25zdCB0eXBlX3N0ciA9IHR5cGVUb1N0cmluZ01hcFt0eXBlXSB8fCBcInVua25vd25cIjtcblxuICAgICAgICBjb25zdCBwYXlsb2FkID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldFBheWxvYWQobWVzc2FnZSwgZW5jb2RpbmcpO1xuXG4gICAgICAgIHJldHVybiBgWyR7c2lkfSwke2Fja30sJHt0eXBlX3N0cn0sWyR7cGF5bG9hZH1dXWBcbiAgICB9XG59XG4iLCAiZXhwb3J0IHR5cGUgRGVidWdMb2dnZXJGdW5jdGlvbiA9IChtc2c6IHN0cmluZywgLi4ucGFyYW1zOiB1bmtub3duW10pID0+IHZvaWQ7XG5cbmV4cG9ydCBmdW5jdGlvbiBDcmVhdGVEZWJ1Z0xvZ2dlcihzZWN0aW9uOiBzdHJpbmcpOiBEZWJ1Z0xvZ2dlckZ1bmN0aW9uIHtcbiAgICBpZiAobG9jYWxTdG9yYWdlLmdldEl0ZW0oXCJDUllPX0RFQlVHXCIpPy5pbmNsdWRlcyhzZWN0aW9uKSkge1xuICAgICAgICByZXR1cm4gKG1zZzogc3RyaW5nLCAuLi5wYXJhbXM6IHVua25vd25bXSkgPT4ge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gbmV3IEVycm9yKCk7XG4gICAgICAgICAgICBjb25zdCBzdGFjayA9IGVyci5zdGFjaz8uc3BsaXQoXCJcXG5cIik7XG4gICAgICAgICAgICBjb25zdCBjYWxsZXJfbGluZSA9IHN0YWNrPy5bMl0gPz8gXCJ1bmtub3duXCI7XG4gICAgICAgICAgICBjb25zdCBtZXRob2RfY2xlYW5lZCA9IGNhbGxlcl9saW5lLnRyaW0oKS5yZXBsYWNlKC9eYXRcXHMrLywgXCJcIik7XG4gICAgICAgICAgICBjb25zdCBtZXRob2QgPSBtZXRob2RfY2xlYW5lZC5zdWJzdHJpbmcoMCwgbWV0aG9kX2NsZWFuZWQuaW5kZXhPZihcIihcIikgLSAxKTtcbiAgICAgICAgICAgIGNvbnN0IHBvc2l0aW9uID0gbWV0aG9kX2NsZWFuZWQuc3Vic3RyaW5nKG1ldGhvZF9jbGVhbmVkLmxhc3RJbmRleE9mKFwiOlwiKSAtIDIsIG1ldGhvZF9jbGVhbmVkLmxlbmd0aCAtIDEpO1xuXG4gICAgICAgICAgICBjb25zb2xlLmluZm8oYCR7c2VjdGlvbi5wYWRFbmQoMjQsIFwiIFwiKX0ke25ldyBEYXRlKCkudG9JU09TdHJpbmcoKS5wYWRFbmQoMzIsIFwiIFwiKX0gJHttZXRob2QucGFkRW5kKDY0LCBcIiBcIil9ICR7cG9zaXRpb24ucGFkRW5kKDgsIFwiIFwiKX0gJHttc2d9YCwgLi4ucGFyYW1zKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuICgpID0+IHtcbiAgICB9O1xufVxuIiwgImltcG9ydCBHdWFyZCBmcm9tIFwiLi4vVXRpbC9HdWFyZC5qc1wiO1xuXG5leHBvcnQgY2xhc3MgQ3J5b0V2ZW50RW1pdHRlcjxFdmVudE1hcCBleHRlbmRzIFJlY29yZDxzdHJpbmcsIGFueT4gPSBSZWNvcmQ8c3RyaW5nLCBhbnk+PiB7XG4gICAgcHJpdmF0ZSB0YXJnZXQgPSBuZXcgRXZlbnRUYXJnZXQoKTtcblxuICAgIHB1YmxpYyBvbjxLIGV4dGVuZHMga2V5b2YgRXZlbnRNYXA+KHR5cGU6IEssIGxpc3RlbmVyOiAocGF5bG9hZDogRXZlbnRNYXBbS10pID0+IHZvaWQpIHtcbiAgICAgICAgR3VhcmQuQ2FzdEFzPHN0cmluZz4odHlwZSk7XG4gICAgICAgIHRoaXMudGFyZ2V0LmFkZEV2ZW50TGlzdGVuZXIodHlwZSwgKGU6IEV2ZW50KSA9PiB7XG4gICAgICAgICAgICBsaXN0ZW5lcigoZSBhcyBDdXN0b21FdmVudCkuZGV0YWlsKTtcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICBwdWJsaWMgZW1pdDxLIGV4dGVuZHMga2V5b2YgRXZlbnRNYXA+KHR5cGU6IEssIHBheWxvYWQ6IEV2ZW50TWFwW0tdKSB7XG4gICAgICAgIEd1YXJkLkNhc3RBczxzdHJpbmc+KHR5cGUpO1xuICAgICAgICB0aGlzLnRhcmdldC5kaXNwYXRjaEV2ZW50KG5ldyBDdXN0b21FdmVudCh0eXBlLCB7ZGV0YWlsOiBwYXlsb2FkfSkpO1xuICAgIH1cbn1cbiIsICJpbXBvcnQge0NyeW9CdWZmZXJ9IGZyb20gXCIuLi9Db21tb24vQ3J5b0J1ZmZlci9DcnlvQnVmZmVyLmpzXCI7XHJcblxyXG50eXBlIEJ1ZmZlciA9IENyeW9CdWZmZXI7XHJcblxyXG5hc3luYyBmdW5jdGlvbiBpbXBvcnRfa2V5KGRhdGE6IEJ1ZmZlciwgdXNhZ2U6IEtleVVzYWdlW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xyXG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxyXG4gICAgICAgIFwicmF3XCIsXHJcbiAgICAgICAgZGF0YS5idWZmZXIsXHJcbiAgICAgICAge25hbWU6IFwiQUVTLUdDTVwifSxcclxuICAgICAgICBmYWxzZSxcclxuICAgICAgICB1c2FnZVxyXG4gICAgKTtcclxufVxyXG5cclxuZnVuY3Rpb24gbWFrZV9hbGdvKGl2OiBCdWZmZXIpOiBBZXNHY21QYXJhbXMge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgICBuYW1lOiBcIkFFUy1HQ01cIixcclxuICAgICAgICBpdjogaXYuYnVmZmVyLFxyXG5cclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIENyeW9DcnlwdG9Cb3gge1xyXG4gICAgcHJpdmF0ZSBub25jZSA9IDA7XHJcblxyXG4gICAgcHJpdmF0ZSByZWFkb25seSBlbmNfa2V5X3Byb21pc2U6IFByb21pc2U8Q3J5cHRvS2V5PjtcclxuICAgIHByaXZhdGUgcmVhZG9ubHkgZGVjX2tleV9wcm9taXNlOiBQcm9taXNlPENyeXB0b0tleT47XHJcblxyXG4gICAgcHVibGljIGNvbnN0cnVjdG9yKGVuY3J5cHRfa2V5OiBCdWZmZXIsIGRlY3J5cHRpb25fa2V5OiBCdWZmZXIpIHtcclxuICAgICAgICB0aGlzLmVuY19rZXlfcHJvbWlzZSA9IGltcG9ydF9rZXkoZW5jcnlwdF9rZXksIFtcImVuY3J5cHRcIl0pO1xyXG4gICAgICAgIHRoaXMuZGVjX2tleV9wcm9taXNlID0gaW1wb3J0X2tleShkZWNyeXB0aW9uX2tleSwgW1wiZGVjcnlwdFwiXSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBjcmVhdGVfaXYoKTogQnVmZmVyIHtcclxuICAgICAgICBjb25zdCBpdiA9IENyeW9CdWZmZXIuYWxsb2MoMTIpO1xyXG4gICAgICAgIGl2LndyaXRlVUludDMyQkUodGhpcy5ub25jZSsrLCA4KTtcclxuICAgICAgICByZXR1cm4gaXY7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGFzeW5jIGVuY3J5cHQocGxhaW46IEJ1ZmZlcik6IFByb21pc2U8QnVmZmVyPiB7XHJcbiAgICAgICAgY29uc3QgaXYgPSB0aGlzLmNyZWF0ZV9pdigpO1xyXG4gICAgICAgIGNvbnN0IGtleSA9IGF3YWl0IHRoaXMuZW5jX2tleV9wcm9taXNlO1xyXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdChtYWtlX2FsZ28oaXYpLCBrZXksIHBsYWluLmJ1ZmZlcik7XHJcblxyXG4gICAgICAgIHJldHVybiBDcnlvQnVmZmVyLmNvbmNhdChbaXYsIG5ldyBDcnlvQnVmZmVyKG5ldyBVaW50OEFycmF5KGVuY3J5cHRlZCkpXSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGFzeW5jIGRlY3J5cHQoY2lwaGVyOiBCdWZmZXIpOiBQcm9taXNlPENyeW9CdWZmZXI+IHtcclxuICAgICAgICBjb25zdCBpdiA9IGNpcGhlci5zdWJhcnJheSgwLCAxMik7XHJcbiAgICAgICAgY29uc3Qga2V5ID0gYXdhaXQgdGhpcy5kZWNfa2V5X3Byb21pc2U7XHJcbiAgICAgICAgY29uc3QgZGF0YV93aXRoX3RhZyA9IGNpcGhlci5zdWJhcnJheSgxMik7XHJcblxyXG4gICAgICAgIGNvbnN0IGRlY3J5cHRlZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVjcnlwdChtYWtlX2FsZ28oaXYpLCBrZXksIGRhdGFfd2l0aF90YWcuYnVmZmVyKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIG5ldyBDcnlvQnVmZmVyKG5ldyBVaW50OEFycmF5KGRlY3J5cHRlZCkpO1xyXG4gICAgfVxyXG59IiwgImltcG9ydCBDcnlvRnJhbWVGb3JtYXR0ZXIgZnJvbSBcIi4uL0NvbW1vbi9DcnlvQmluYXJ5TWVzc2FnZS9DcnlvRnJhbWVGb3JtYXR0ZXIuanNcIjtcclxuaW1wb3J0IHtDcnlvQnVmZmVyfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9CdWZmZXIvQ3J5b0J1ZmZlci5qc1wiO1xyXG5cclxudHlwZSBCdWZmZXIgPSBDcnlvQnVmZmVyO1xyXG5cclxuZXhwb3J0IGVudW0gSGFuZHNoYWtlU3RhdGUge1xyXG4gICAgSU5JVElBTCA9IDAsXHJcbiAgICBXQUlUX1NFUlZFUl9IRUxMTyA9IDEsXHJcbiAgICBXQUlUX1NFUlZFUl9ET05FID0gMixcclxuICAgIFNFQ1VSRSA9IDNcclxufVxyXG5cclxudHlwZSBDcnlwdG9LZXlzID0geyByZWNlaXZlX2tleTogQnVmZmVyLCB0cmFuc21pdF9rZXk6IEJ1ZmZlciB9O1xyXG50eXBlIFVVSUQgPSBgJHtzdHJpbmd9LSR7c3RyaW5nfS0ke3N0cmluZ30tJHtzdHJpbmd9LSR7c3RyaW5nfWA7XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIEhhbmRzaGFrZUV2ZW50cyB7XHJcbiAgICBvblNlY3VyZTogKGtleXM6IENyeXB0b0tleXMpID0+IHZvaWQ7XHJcbiAgICBvbkZhaWx1cmU6IChyZWFzb246IHN0cmluZykgPT4gdm9pZDtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIENyeW9IYW5kc2hha2VFbmdpbmUge1xyXG4gICAgcHJpdmF0ZSByZWFkb25seSBFQ0RIX0FMR086IEVjS2V5R2VuUGFyYW1zID0ge25hbWU6IFwiRUNESFwiLCBuYW1lZEN1cnZlOiBcIlAtMjU2XCJ9O1xyXG4gICAgcHJpdmF0ZSBoYW5kc2hha2Vfc3RhdGU6IEhhbmRzaGFrZVN0YXRlID0gSGFuZHNoYWtlU3RhdGUuSU5JVElBTDtcclxuICAgIHByaXZhdGUgZWNkaDogQ3J5cHRvS2V5UGFpciB8IG51bGwgPSBudWxsO1xyXG4gICAgcHJpdmF0ZSByZWNlaXZlX2tleTogQnVmZmVyIHwgbnVsbCA9IG51bGw7XHJcbiAgICBwcml2YXRlIHRyYW5zbWl0X2tleTogQnVmZmVyIHwgbnVsbCA9IG51bGw7XHJcblxyXG4gICAgcHVibGljIGNvbnN0cnVjdG9yKFxyXG4gICAgICAgIHByaXZhdGUgcmVhZG9ubHkgc2lkOiBVVUlELFxyXG4gICAgICAgIHByaXZhdGUgc2VuZF9wbGFpbjogKGJ1ZjogQnVmZmVyKSA9PiBQcm9taXNlPHZvaWQ+LFxyXG4gICAgICAgIHByaXZhdGUgZm9ybWF0dGVyOiB0eXBlb2YgQ3J5b0ZyYW1lRm9ybWF0dGVyLFxyXG4gICAgICAgIHByaXZhdGUgbmV4dF9hY2s6ICgpID0+IG51bWJlcixcclxuICAgICAgICBwcml2YXRlIGV2ZW50czogSGFuZHNoYWtlRXZlbnRzXHJcbiAgICApIHtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGFzeW5jIGluaXRfa2V5cygpIHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICB0aGlzLmVjZGggPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxyXG4gICAgICAgICAgICAgICAgdGhpcy5FQ0RIX0FMR08sXHJcbiAgICAgICAgICAgICAgICB0cnVlLFxyXG4gICAgICAgICAgICAgICAgW1wiZGVyaXZlQml0c1wiXVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRzaGFrZV9zdGF0ZSA9IEhhbmRzaGFrZVN0YXRlLldBSVRfU0VSVkVSX0hFTExPO1xyXG4gICAgICAgIH0gY2F0Y2ggKGV4KSB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzLm9uRmFpbHVyZShgRmFpbGVkIHRvIGdlbmVyYXRlIEVDREgga2V5czogJHtleH1gKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGFzeW5jIG9uX3NlcnZlcl9oZWxsbyhmcmFtZTogQnVmZmVyKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgICAgICAgaWYgKCF0aGlzLmVjZGgpXHJcbiAgICAgICAgICAgIGF3YWl0IHRoaXMuaW5pdF9rZXlzKCk7XHJcblxyXG4gICAgICAgIGlmICh0aGlzLmhhbmRzaGFrZV9zdGF0ZSAhPT0gSGFuZHNoYWtlU3RhdGUuV0FJVF9TRVJWRVJfSEVMTE8pIHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHMub25GYWlsdXJlKGBDTElFTlRfSEVMTE8gcmVjZWl2ZWQgd2hpbGUgaW4gc3RhdGUgJHt0aGlzLmhhbmRzaGFrZV9zdGF0ZX1gKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgZGVjb2RlZCA9IENyeW9GcmFtZUZvcm1hdHRlclxyXG4gICAgICAgICAgICAuR2V0Rm9ybWF0dGVyKFwic2VydmVyX2hlbGxvXCIpXHJcbiAgICAgICAgICAgIC5EZXNlcmlhbGl6ZShmcmFtZSk7XHJcblxyXG4gICAgICAgIGNvbnN0IHNlcnZlcl9wdWJfa2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXCJyYXdcIiwgZGVjb2RlZC5wYXlsb2FkLmJ1ZmZlciwgdGhpcy5FQ0RIX0FMR08sIGZhbHNlLCBbXSk7XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5lY2RoPy5wcml2YXRlS2V5KSB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzLm9uRmFpbHVyZShcIkxvY2FsIEVDREggcHJpdmF0ZSBrZXkgbm90IGluaXRpYWxpc2VkLlwiKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3Qgc2VjcmV0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKHtcclxuICAgICAgICAgICAgbmFtZTogXCJFQ0RIXCIsXHJcbiAgICAgICAgICAgIHB1YmxpYzogc2VydmVyX3B1Yl9rZXlcclxuICAgICAgICB9LCB0aGlzLmVjZGgucHJpdmF0ZUtleSwgMjU2KTtcclxuICAgICAgICBjb25zdCBoYXNoID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIHNlY3JldCkpO1xyXG5cclxuICAgICAgICB0aGlzLnRyYW5zbWl0X2tleSA9IG5ldyBDcnlvQnVmZmVyKGhhc2guc3ViYXJyYXkoMTYsIDMyKSk7XHJcbiAgICAgICAgdGhpcy5yZWNlaXZlX2tleSA9IG5ldyBDcnlvQnVmZmVyKGhhc2guc3ViYXJyYXkoMCwgMTYpKTtcclxuXHJcbiAgICAgICAgY29uc3QgbXlfcHViX2tleSA9IG5ldyBDcnlvQnVmZmVyKG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwicmF3XCIsIHRoaXMuZWNkaC5wdWJsaWNLZXkpKSk7XHJcblxyXG4gICAgICAgIGNvbnN0IGFjayA9IHRoaXMubmV4dF9hY2soKTtcclxuXHJcbiAgICAgICAgY29uc3QgY2xpZW50X2hlbGxvID0gdGhpcy5mb3JtYXR0ZXJcclxuICAgICAgICAgICAgLkdldEZvcm1hdHRlcihcImNsaWVudF9oZWxsb1wiKVxyXG4gICAgICAgICAgICAuU2VyaWFsaXplKHRoaXMuc2lkLCBhY2ssIG15X3B1Yl9rZXkpO1xyXG5cclxuICAgICAgICBhd2FpdCB0aGlzLnNlbmRfcGxhaW4oY2xpZW50X2hlbGxvKTtcclxuICAgICAgICB0aGlzLmhhbmRzaGFrZV9zdGF0ZSA9IEhhbmRzaGFrZVN0YXRlLldBSVRfU0VSVkVSX0RPTkU7XHJcbiAgICB9XHJcblxyXG4gICAgLypcclxuICAgICogICAgICAgICBpZiAodGhpcy5oYW5kc2hha2Vfc3RhdGUgIT09IEhhbmRzaGFrZVN0YXRlLldBSVRfU0VSVkVSX0RPTkUpIHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHMub25GYWlsdXJlKGBIQU5EU0hBS0VfRE9ORSByZWNlaXZlZCB3aGlsZSBpbiBzdGF0ZSAke3RoaXMuc3RhdGV9YCk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcbiAgICAgICAgY29uc29sZS5lcnJvcihcIkNMSUVOVCBHT1QgU0VSVkVSIEhBTkRTSEFLRSFcIilcclxuICAgICAgICBjb25zdCBkZWNvZGVkID0gQ3J5b0ZyYW1lRm9ybWF0dGVyXHJcbiAgICAgICAgICAgIC5HZXRGb3JtYXR0ZXIoXCJoYW5kc2hha2VfZG9uZVwiKVxyXG4gICAgICAgICAgICAuRGVzZXJpYWxpemUoZnJhbWUpO1xyXG5cclxuICAgICAgICBjb25zdCBkb25lID0gQ3J5b0ZyYW1lRm9ybWF0dGVyXHJcbiAgICAgICAgICAgIC5HZXRGb3JtYXR0ZXIoXCJoYW5kc2hha2VfZG9uZVwiKVxyXG4gICAgICAgICAgICAuU2VyaWFsaXplKHRoaXMuc2lkLCBkZWNvZGVkLmFjaywgbnVsbCk7XHJcbiAgICAgICAgYXdhaXQgdGhpcy5zZW5kX3BsYWluKGRvbmUpO1xyXG5cclxuICAgICAgICB0aGlzLmV2ZW50cy5vblNlY3VyZSh7cmVjZWl2ZV9rZXk6IHRoaXMucmVjZWl2ZV9rZXksIHRyYW5zbWl0X2tleTogdGhpcy50cmFuc21pdF9rZXl9KTtcclxuICAgICAgICAvL0NsaWVudCBnb3Qgb3VyIFNFUlZFUl9IRUxMTyBhbmQgZmluaXNoZWQgb24gaXRzIHNpZGVcclxuICAgICAgICB0aGlzLmhhbmRzaGFrZV9zdGF0ZSA9IEhhbmRzaGFrZVN0YXRlLlNFQ1VSRTtcclxuXHJcbiAgICAqICovXHJcbiAgICBwdWJsaWMgYXN5bmMgb25fc2VydmVyX2hhbmRzaGFrZV9kb25lKGZyYW1lOiBCdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcclxuICAgICAgICBpZiAodGhpcy5oYW5kc2hha2Vfc3RhdGUgIT09IEhhbmRzaGFrZVN0YXRlLldBSVRfU0VSVkVSX0RPTkUpIHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHMub25GYWlsdXJlKGBIQU5EU0hBS0VfRE9ORSByZWNlaXZlZCB3aGlsZSBpbiBzdGF0ZSAke3RoaXMuc3RhdGV9YCk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIC8vQ2xpZW50IGdvdCBvdXIgU0VSVkVSX0hFTExPIGFuZCBmaW5pc2hlZCBvbiBpdHMgc2lkZVxyXG4gICAgICAgIC8vTm93IHdlJ2xsIHNlbmQgb3VyIGhhbmRzaGFrZV9kb25lIGZyYW1lXHJcbiAgICAgICAgY29uc3QgZGVjb2RlZCA9IENyeW9GcmFtZUZvcm1hdHRlclxyXG4gICAgICAgICAgICAuR2V0Rm9ybWF0dGVyKFwiaGFuZHNoYWtlX2RvbmVcIilcclxuICAgICAgICAgICAgLkRlc2VyaWFsaXplKGZyYW1lKTtcclxuXHJcbiAgICAgICAgY29uc3QgZG9uZSA9IENyeW9GcmFtZUZvcm1hdHRlclxyXG4gICAgICAgICAgICAuR2V0Rm9ybWF0dGVyKFwiaGFuZHNoYWtlX2RvbmVcIilcclxuICAgICAgICAgICAgLlNlcmlhbGl6ZSh0aGlzLnNpZCwgZGVjb2RlZC5hY2ssIG51bGwpO1xyXG4gICAgICAgIGF3YWl0IHRoaXMuc2VuZF9wbGFpbihkb25lKTtcclxuXHJcbiAgICAgICAgdGhpcy5ldmVudHMub25TZWN1cmUoe3JlY2VpdmVfa2V5OiB0aGlzLnJlY2VpdmVfa2V5ISwgdHJhbnNtaXRfa2V5OiB0aGlzLnRyYW5zbWl0X2tleSF9KTtcclxuICAgICAgICB0aGlzLmhhbmRzaGFrZV9zdGF0ZSA9IEhhbmRzaGFrZVN0YXRlLlNFQ1VSRTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0IGlzX3NlY3VyZSgpOiBib29sZWFuIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5oYW5kc2hha2Vfc3RhdGUgPT09IEhhbmRzaGFrZVN0YXRlLlNFQ1VSRTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0IHN0YXRlKCk6IEhhbmRzaGFrZVN0YXRlIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5oYW5kc2hha2Vfc3RhdGU7XHJcbiAgICB9XHJcbn0iLCAiaW1wb3J0IENyeW9GcmFtZUZvcm1hdHRlciwge0JpbmFyeU1lc3NhZ2VUeXBlfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9CaW5hcnlNZXNzYWdlL0NyeW9GcmFtZUZvcm1hdHRlci5qc1wiO1xyXG5pbXBvcnQge0NyZWF0ZURlYnVnTG9nZ2VyLCBEZWJ1Z0xvZ2dlckZ1bmN0aW9ufSBmcm9tIFwiLi4vQ29tbW9uL1V0aWwvQ3JlYXRlRGVidWdMb2dnZXIuanNcIjtcclxuaW1wb3J0IHtDcnlvQnVmZmVyfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9CdWZmZXIvQ3J5b0J1ZmZlci5qc1wiO1xyXG50eXBlIEJ1ZmZlciA9IENyeW9CdWZmZXI7XHJcblxyXG5pbnRlcmZhY2UgUm91dGVySGFuZGxlcnMge1xyXG4gICAgLy9Ob3JtYWwgZnJhbWUgcm91dGluZ1xyXG4gICAgb25fcGluZ19wb25nOiAoZnJhbWU6IEJ1ZmZlcikgPT4gUHJvbWlzZTx2b2lkPjtcclxuICAgIG9uX2FjazogKGZyYW1lOiBCdWZmZXIpID0+IFByb21pc2U8dm9pZD47XHJcbiAgICBvbl9lcnJvcjogKGZyYW1lOiBCdWZmZXIpID0+IFByb21pc2U8dm9pZD47XHJcbiAgICBvbl91dGY4OiAoZnJhbWU6IEJ1ZmZlcikgPT4gUHJvbWlzZTx2b2lkPjtcclxuICAgIG9uX2JpbmFyeTogKGZyYW1lOiBCdWZmZXIpID0+IFByb21pc2U8dm9pZD47XHJcblxyXG4gICAgLy9IYW5kc2hha2UgZnJhbWUgcm91dGluZyBzaG91bGQgZ28gdG8gdGhlIEhhbmRzaGFrZUVuZ2luZVxyXG4gICAgb25fc2VydmVyX2hlbGxvPzogKGZyYW1lOiBCdWZmZXIpID0+IFByb21pc2U8dm9pZD47XHJcbiAgICBvbl9jbGllbnRfaGVsbG8/OiAoZnJhbWU6IEJ1ZmZlcikgPT4gUHJvbWlzZTx2b2lkPjtcclxuICAgIG9uX2hhbmRzaGFrZV9kb25lPzogKGZyYW1lOiBCdWZmZXIpID0+IFByb21pc2U8dm9pZD47XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBDcnlvRnJhbWVSb3V0ZXIge1xyXG4gICAgcHVibGljIGNvbnN0cnVjdG9yKFxyXG4gICAgICAgIHByaXZhdGUgcmVhZG9ubHkgZm9ybWF0dGVyOiB0eXBlb2YgQ3J5b0ZyYW1lRm9ybWF0dGVyLFxyXG4gICAgICAgIHByaXZhdGUgcmVhZG9ubHkgaXNfc2VjdXJlOiAoKSA9PiBib29sZWFuLFxyXG4gICAgICAgIHByaXZhdGUgcmVhZG9ubHkgZGVjcnlwdDogKGJ1ZmZlcjogQnVmZmVyKSA9PiBQcm9taXNlPEJ1ZmZlcj4sXHJcbiAgICAgICAgcHJpdmF0ZSByZWFkb25seSBoYW5kbGVyczogUm91dGVySGFuZGxlcnMsXHJcbiAgICAgICAgcHJpdmF0ZSBsb2c6IERlYnVnTG9nZ2VyRnVuY3Rpb24gPSBDcmVhdGVEZWJ1Z0xvZ2dlcihcIkNSWU9fRlJBTUVfUk9VVEVSXCIpXHJcbiAgICApIHtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHRyeV9nZXRfdHlwZShmcmFtZTogQnVmZmVyKTogQmluYXJ5TWVzc2FnZVR5cGUgfCBudWxsIHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICByZXR1cm4gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldFR5cGUoZnJhbWUpO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHtcclxuICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIC8qICAgICAgICBpZighYnVmIHx8IGJ1Zi5sZW5ndGggPCAyMSlcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcclxuXHJcbiAgICAgICAgICAgICAgICBjb25zdCB0eXBlX2J5dGUgPSBidWYucmVhZFVpbnQ4KDIwKTtcclxuICAgICAgICAgICAgICAgIHJldHVybiB0eXBlX2J5dGUgPD0gQmluYXJ5TWVzc2FnZVR5cGUuSEFORFNIQUtFX0RPTkUgPyB0eXBlX2J5dGUgYXMgQmluYXJ5TWVzc2FnZVR5cGUgOiBudWxsOyovXHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGFzeW5jIGRvX3JvdXRlKHJhdzogQnVmZmVyKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgICAgICAgbGV0IGZyYW1lOiBCdWZmZXIgPSByYXc7XHJcbiAgICAgICAgbGV0IHR5cGU6IEJpbmFyeU1lc3NhZ2VUeXBlIHwgbnVsbCA9IHRoaXMudHJ5X2dldF90eXBlKHJhdyk7XHJcblxyXG4gICAgICAgIGlmICh0eXBlID09PSBudWxsICYmIHRoaXMuaXNfc2VjdXJlKCkpIHtcclxuICAgICAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgICAgIGZyYW1lID0gYXdhaXQgdGhpcy5kZWNyeXB0KHJhdyk7XHJcbiAgICAgICAgICAgICAgICB0eXBlID0gdGhpcy50cnlfZ2V0X3R5cGUoZnJhbWUpO1xyXG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZyhgRGVjcnlwdGlvbiBmYWlsZWQ6ICR7ZX1gLCByYXcpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAodHlwZSA9PT0gbnVsbCkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZyhgVW5rbm93biBmcmFtZSB0eXBlYCwgcmF3KTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XHJcbiAgICAgICAgICAgIGNhc2UgQmluYXJ5TWVzc2FnZVR5cGUuUElOR19QT05HOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl9waW5nX3BvbmcoZnJhbWUpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkVSUk9SOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl9lcnJvcihmcmFtZSk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIGNhc2UgQmluYXJ5TWVzc2FnZVR5cGUuQUNLOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl9hY2soZnJhbWUpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLlVURjhEQVRBOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl91dGY4KGZyYW1lKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgY2FzZSBCaW5hcnlNZXNzYWdlVHlwZS5CSU5BUllEQVRBOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl9iaW5hcnkoZnJhbWUpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLlNFUlZFUl9IRUxMTzpcclxuICAgICAgICAgICAgICAgIGF3YWl0IHRoaXMuaGFuZGxlcnMub25fc2VydmVyX2hlbGxvPy4oZnJhbWUpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkNMSUVOVF9IRUxMTzpcclxuICAgICAgICAgICAgICAgIGF3YWl0IHRoaXMuaGFuZGxlcnMub25fY2xpZW50X2hlbGxvPy4oZnJhbWUpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICBjYXNlIEJpbmFyeU1lc3NhZ2VUeXBlLkhBTkRTSEFLRV9ET05FOlxyXG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5oYW5kbGVycy5vbl9oYW5kc2hha2VfZG9uZT8uKGZyYW1lKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nKGBVbnN1cHBvcnRlZCBiaW5hcnkgbWVzc2FnZSB0eXBlICR7dHlwZX0hYCk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59IiwgImltcG9ydCB7SUNyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uRXZlbnRzLCBQZW5kaW5nQmluYXJ5TWVzc2FnZX0gZnJvbSBcIi4vdHlwZXMvQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24uanNcIjtcbmltcG9ydCB7QWNrVHJhY2tlcn0gZnJvbSBcIi4uL0NvbW1vbi9BY2tUcmFja2VyL0Fja1RyYWNrZXIuanNcIjtcbmltcG9ydCBDcnlvRnJhbWVGb3JtYXR0ZXIsIHtCaW5hcnlNZXNzYWdlVHlwZX0gZnJvbSBcIi4uL0NvbW1vbi9DcnlvQmluYXJ5TWVzc2FnZS9DcnlvRnJhbWVGb3JtYXR0ZXIuanNcIjtcbmltcG9ydCB7Q3J5b0ZyYW1lSW5zcGVjdG9yfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9GcmFtZUluc3BlY3Rvci9DcnlvRnJhbWVJbnNwZWN0b3IuanNcIjtcbmltcG9ydCB7Q3JlYXRlRGVidWdMb2dnZXIsIERlYnVnTG9nZ2VyRnVuY3Rpb259IGZyb20gXCIuLi9Db21tb24vVXRpbC9DcmVhdGVEZWJ1Z0xvZ2dlci5qc1wiO1xuaW1wb3J0IHtDcnlvQnVmZmVyfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9CdWZmZXIvQ3J5b0J1ZmZlci5qc1wiO1xuaW1wb3J0IHtDcnlvRXZlbnRFbWl0dGVyfSBmcm9tIFwiLi4vQ29tbW9uL0NyeW9FdmVudEVtaXR0ZXIvQ3J5b0V2ZW50RW1pdHRlci5qc1wiO1xuaW1wb3J0IHtDcnlvQ3J5cHRvQm94fSBmcm9tIFwiLi9DcnlvQ3J5cHRvQm94LmpzXCI7XG5pbXBvcnQge0NyeW9IYW5kc2hha2VFbmdpbmUsIEhhbmRzaGFrZUV2ZW50c30gZnJvbSBcIi4vQ3J5b0hhbmRzaGFrZUVuZ2luZS5qc1wiO1xuaW1wb3J0IHtDcnlvRnJhbWVSb3V0ZXJ9IGZyb20gXCIuL0NyeW9GcmFtZVJvdXRlci5qc1wiO1xuXG50eXBlIFVVSUQgPSBgJHtzdHJpbmd9LSR7c3RyaW5nfS0ke3N0cmluZ30tJHtzdHJpbmd9LSR7c3RyaW5nfWA7XG5cbmVudW0gQ2xvc2VDb2RlIHtcbiAgICBDTE9TRV9HUkFDRUZVTCA9IDQwMDAsXG4gICAgQ0xPU0VfQ0xJRU5UX0VSUk9SID0gNDAwMSxcbiAgICBDTE9TRV9TRVJWRVJfRVJST1IgPSA0MDAyLFxuICAgIENMT1NFX0NBTEVfTUlTTUFUQ0ggPSA0MDEwLFxuICAgIENMT1NFX0NBTEVfSEFORFNIQUtFID0gNDAxMVxufVxuXG50eXBlIEJ1ZmZlciA9IENyeW9CdWZmZXI7XG5cbmZ1bmN0aW9uIG9uY2U8VCBleHRlbmRzIGtleW9mIFdlYlNvY2tldEV2ZW50TWFwPihzb2NrZXQ6IFdlYlNvY2tldCwgdHlwZTogVCwgaGFuZGxlcjogKGV2OiBXZWJTb2NrZXRFdmVudE1hcFtUXSkgPT4gdm9pZCkge1xuICAgIGNvbnN0IHdyYXBwZXIgPSAoZXY6IFdlYlNvY2tldEV2ZW50TWFwW1RdKSA9PiB7XG4gICAgICAgIHNvY2tldC5yZW1vdmVFdmVudExpc3RlbmVyKHR5cGUsIHdyYXBwZXIpO1xuICAgICAgICBoYW5kbGVyKGV2KTtcbiAgICB9O1xuICAgIHNvY2tldC5hZGRFdmVudExpc3RlbmVyKHR5cGUsIHdyYXBwZXIpO1xufVxuXG4vKlxuKiBDcnlvIFdlYnNvY2tldCBzZXNzaW9uIGxheWVyLiBIYW5kbGVzIEJpbmFyeSBmb3JtYXR0aW5nIGFuZCBBQ0tzIGFuZCB3aGF0bm90XG4qICovXG5leHBvcnQgY2xhc3MgQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24gZXh0ZW5kcyBDcnlvRXZlbnRFbWl0dGVyPElDcnlvQ2xpZW50V2Vic29ja2V0U2Vzc2lvbkV2ZW50cz4gaW1wbGVtZW50cyBDcnlvQ2xpZW50V2Vic29ja2V0U2Vzc2lvbiB7XG4gICAgcHJpdmF0ZSBtZXNzYWdlc19wZW5kaW5nX3NlcnZlcl9hY2sgPSBuZXcgTWFwPG51bWJlciwgUGVuZGluZ0JpbmFyeU1lc3NhZ2U+KCk7XG4gICAgcHJpdmF0ZSBzZXJ2ZXJfYWNrX3RyYWNrZXI6IEFja1RyYWNrZXIgPSBuZXcgQWNrVHJhY2tlcigpO1xuICAgIHByaXZhdGUgY3VycmVudF9hY2sgPSAwO1xuXG4gICAgcHJpdmF0ZSByZWFkb25seSBwaW5nX3BvbmdfZm9ybWF0dGVyID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldEZvcm1hdHRlcihcInBpbmdfcG9uZ1wiKTtcbiAgICBwcml2YXRlIHJlYWRvbmx5IGFja19mb3JtYXR0ZXIgPSBDcnlvRnJhbWVGb3JtYXR0ZXIuR2V0Rm9ybWF0dGVyKFwiYWNrXCIpO1xuICAgIHByaXZhdGUgcmVhZG9ubHkgZXJyb3JfZm9ybWF0dGVyID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldEZvcm1hdHRlcihcImVycm9yXCIpO1xuICAgIHByaXZhdGUgcmVhZG9ubHkgdXRmOF9mb3JtYXR0ZXIgPSBDcnlvRnJhbWVGb3JtYXR0ZXIuR2V0Rm9ybWF0dGVyKFwidXRmOGRhdGFcIik7XG4gICAgcHJpdmF0ZSByZWFkb25seSBiaW5hcnlfZm9ybWF0dGVyID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldEZvcm1hdHRlcihcImJpbmFyeWRhdGFcIik7XG5cbiAgICBwcml2YXRlIGNyeXB0bzogQ3J5b0NyeXB0b0JveCB8IG51bGwgPSBudWxsO1xuICAgIHByaXZhdGUgaGFuZHNoYWtlOiBDcnlvSGFuZHNoYWtlRW5naW5lIHwgbnVsbCA9IG51bGw7XG4gICAgcHJpdmF0ZSByb3V0ZXI6IENyeW9GcmFtZVJvdXRlcjtcblxuICAgIHByaXZhdGUgY29uc3RydWN0b3IocHJpdmF0ZSBob3N0OiBzdHJpbmcsIHByaXZhdGUgc2lkOiBVVUlELCBwcml2YXRlIHNvY2tldDogV2ViU29ja2V0LCBwcml2YXRlIHRpbWVvdXQ6IG51bWJlciwgcHJpdmF0ZSBiZWFyZXI6IHN0cmluZywgcHJpdmF0ZSB1c2VfY2FsZTogYm9vbGVhbiwgcHJpdmF0ZSBsb2c6IERlYnVnTG9nZ2VyRnVuY3Rpb24gPSBDcmVhdGVEZWJ1Z0xvZ2dlcihcIkNSWU9fQ0xJRU5UX1NFU1NJT05cIikpIHtcbiAgICAgICAgc3VwZXIoKTtcbiAgICAgICAgaWYgKHVzZV9jYWxlKSB7XG4gICAgICAgICAgICBjb25zdCBoYW5kc2hha2VfZXZlbnRzOiBIYW5kc2hha2VFdmVudHMgPSB7XG4gICAgICAgICAgICAgICAgb25TZWN1cmU6ICh7dHJhbnNtaXRfa2V5LCByZWNlaXZlX2tleX0pID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5jcnlwdG8gPSBuZXcgQ3J5b0NyeXB0b0JveCh0cmFuc21pdF9rZXksIHJlY2VpdmVfa2V5KTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2coXCJDaGFubmVsIHNlY3VyZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmVtaXQoXCJjb25uZWN0ZWRcIiwgdW5kZWZpbmVkKTsgLy8gb25seSBlbWl0IG9uY2Ugd2VcdTIwMTlyZSBzZWN1cmVcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIG9uRmFpbHVyZTogKHJlYXNvbjogc3RyaW5nKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nKGBIYW5kc2hha2UgZmFpbHVyZTogJHtyZWFzb259YCk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuRGVzdHJveShDbG9zZUNvZGUuQ0xPU0VfQ0FMRV9IQU5EU0hBS0UsIFwiRmFpbHVyZSBkdXJpbmcgQ0FMRSBoYW5kc2hha2UuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHRoaXMuaGFuZHNoYWtlID0gbmV3IENyeW9IYW5kc2hha2VFbmdpbmUoXG4gICAgICAgICAgICAgICAgdGhpcy5zaWQsXG4gICAgICAgICAgICAgICAgYXN5bmMgKGJ1ZikgPT4gdGhpcy5zb2NrZXQuc2VuZChidWYuYnVmZmVyKSwgLy8gcmF3IHBsYWludGV4dCBzZW5kXG4gICAgICAgICAgICAgICAgQ3J5b0ZyYW1lRm9ybWF0dGVyLFxuICAgICAgICAgICAgICAgICgpID0+IHRoaXMuY3VycmVudF9hY2srKyxcbiAgICAgICAgICAgICAgICBoYW5kc2hha2VfZXZlbnRzLFxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5yb3V0ZXIgPSBuZXcgQ3J5b0ZyYW1lUm91dGVyKFxuICAgICAgICAgICAgICAgIENyeW9GcmFtZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAoKSA9PiB0aGlzLmhhbmRzaGFrZSEuaXNfc2VjdXJlLFxuICAgICAgICAgICAgICAgIGFzeW5jIChiKSA9PiB0aGlzLmNyeXB0byEuZGVjcnlwdChiKSxcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIG9uX3BpbmdfcG9uZzogYXN5bmMgKGIpID0+IHRoaXMuSGFuZGxlUGluZ1BvbmdNZXNzYWdlKGIpLFxuICAgICAgICAgICAgICAgICAgICBvbl9hY2s6IGFzeW5jIChiKSA9PiB0aGlzLkhhbmRsZUFja01lc3NhZ2UoYiksXG4gICAgICAgICAgICAgICAgICAgIG9uX2Vycm9yOiBhc3luYyAoYikgPT4gdGhpcy5IYW5kbGVFcnJvck1lc3NhZ2UoYiksXG4gICAgICAgICAgICAgICAgICAgIG9uX3V0Zjg6IGFzeW5jIChiKSA9PiB0aGlzLkhhbmRsZVVURjhEYXRhTWVzc2FnZShiKSxcbiAgICAgICAgICAgICAgICAgICAgb25fYmluYXJ5OiBhc3luYyAoYikgPT4gdGhpcy5IYW5kbGVCaW5hcnlEYXRhTWVzc2FnZShiKSxcblxuICAgICAgICAgICAgICAgICAgICBvbl9zZXJ2ZXJfaGVsbG86IGFzeW5jIChiKSA9PiB0aGlzLmhhbmRzaGFrZSEub25fc2VydmVyX2hlbGxvKGIpLFxuICAgICAgICAgICAgICAgICAgICBvbl9oYW5kc2hha2VfZG9uZTogYXN5bmMgKGIpID0+IHRoaXMuaGFuZHNoYWtlIS5vbl9zZXJ2ZXJfaGFuZHNoYWtlX2RvbmUoYilcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5sb2coXCJDQUxFIGRpc2FibGVkLCBydW5uaW5nIGluIHVuZW5jcnlwdGVkIG1vZGUuXCIpO1xuICAgICAgICAgICAgdGhpcy5yb3V0ZXIgPSBuZXcgQ3J5b0ZyYW1lUm91dGVyKFxuICAgICAgICAgICAgICAgIENyeW9GcmFtZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAoKSA9PiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhc3luYyAoYikgPT4gYixcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIG9uX3BpbmdfcG9uZzogYXN5bmMgKGIpID0+IHRoaXMuSGFuZGxlUGluZ1BvbmdNZXNzYWdlKGIpLFxuICAgICAgICAgICAgICAgICAgICBvbl9hY2s6IGFzeW5jIChiKSA9PiB0aGlzLkhhbmRsZUFja01lc3NhZ2UoYiksXG4gICAgICAgICAgICAgICAgICAgIG9uX2Vycm9yOiBhc3luYyAoYikgPT4gdGhpcy5IYW5kbGVFcnJvck1lc3NhZ2UoYiksXG4gICAgICAgICAgICAgICAgICAgIG9uX3V0Zjg6IGFzeW5jIChiKSA9PiB0aGlzLkhhbmRsZVVURjhEYXRhTWVzc2FnZShiKSxcbiAgICAgICAgICAgICAgICAgICAgb25fYmluYXJ5OiBhc3luYyAoYikgPT4gdGhpcy5IYW5kbGVCaW5hcnlEYXRhTWVzc2FnZShiKSxcbiAgICAgICAgICAgICAgICAgICAgb25fc2VydmVyX2hlbGxvOiBhc3luYyAoX2IpID0+IHRoaXMuRGVzdHJveShDbG9zZUNvZGUuQ0xPU0VfQ0FMRV9NSVNNQVRDSCwgXCJDQUxFIE1pc21hdGNoLiBUaGUgc2VydmVyIGV4Y2VwdHMgQ0FMRSBlbmNyeXB0aW9uLCB3aGljaCBpcyBjdXJyZW50bHkgZGlzYWJsZWQuXCIpXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmVtaXQoXCJjb25uZWN0ZWRcIiwgdW5kZWZpbmVkKSk7XG4gICAgICAgIH1cblxuXG4gICAgICAgIHRoaXMuQXR0YWNoTGlzdGVuZXJzVG9Tb2NrZXQoc29ja2V0KTtcbiAgICB9XG5cbiAgICBwcml2YXRlIEF0dGFjaExpc3RlbmVyc1RvU29ja2V0KHNvY2tldDogV2ViU29ja2V0KSB7XG4gICAgICAgIGlmICh0aGlzLnVzZV9jYWxlKSB7XG4gICAgICAgICAgICBvbmNlKHNvY2tldCwgXCJtZXNzYWdlXCIsIChtc2c6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgICAgIC8vSWYgdGhlIGZpcnN0IHJlYWQgZnJhbWUgSVMgTk9UIFNFUlZFUl9IRUxMTywgZmFpbCBhbmQgZGllIGluIGFuIGV4cGxvc2lvbi5cbiAgICAgICAgICAgICAgICBpZiAoIShtc2cuZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSlcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuXG4gICAgICAgICAgICAgICAgY29uc3QgcmF3ID0gbmV3IENyeW9CdWZmZXIobmV3IFVpbnQ4QXJyYXkobXNnLmRhdGEpKTtcbiAgICAgICAgICAgICAgICBjb25zdCB0eXBlID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldFR5cGUocmF3KTtcblxuICAgICAgICAgICAgICAgIGlmICh0eXBlICE9PSBCaW5hcnlNZXNzYWdlVHlwZS5TRVJWRVJfSEVMTE8pIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2coYENBTEUgbWlzbWF0Y2g6IGV4cGVjdGVkIFNFUlZFUl9IRUxMTywgZ290ICR7dHlwZX1gKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5EZXN0cm95KENsb3NlQ29kZS5DTE9TRV9DQUxFX01JU01BVENILCBcIkNBTEUgbWlzbWF0Y2g6IFRoZSBzZXJ2ZXIgaGFzIGRpc2FibGVkIENBTEUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdGhpcy5yb3V0ZXIuZG9fcm91dGUocmF3KS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgc29ja2V0LmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIGFzeW5jIChtc2c6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1zZy5kYXRhIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5yb3V0ZXIuZG9fcm91dGUobmV3IENyeW9CdWZmZXIobmV3IFVpbnQ4QXJyYXkobXNnLmRhdGEpKSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNvY2tldC5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBhc3luYyAobXNnOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgICAgICBpZiAobXNnLmRhdGEgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcilcbiAgICAgICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5yb3V0ZXIuZG9fcm91dGUobmV3IENyeW9CdWZmZXIobmV3IFVpbnQ4QXJyYXkobXNnLmRhdGEpKSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHNvY2tldC5hZGRFdmVudExpc3RlbmVyKFwiZXJyb3JcIiwgYXN5bmMgKGVycm9yX2V2ZW50KSA9PiB7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLkhhbmRsZUVycm9yKG5ldyBFcnJvcihcIlVuc3BlY2lmaWVkIFdlYlNvY2tldCBlcnJvciFcIiwge2NhdXNlOiBlcnJvcl9ldmVudH0pKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgc29ja2V0LmFkZEV2ZW50TGlzdGVuZXIoXCJjbG9zZVwiLCBhc3luYyAoY2xvc2VfZXZlbnQpID0+IHtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMuSGFuZGxlQ2xvc2UoY2xvc2VfZXZlbnQuY29kZSwgbmV3IENyeW9CdWZmZXIoKG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShjbG9zZV9ldmVudC5yZWFzb24pKSkpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcml2YXRlIHN0YXRpYyBhc3luYyBDb25zdHJ1Y3RTb2NrZXQoaG9zdDogc3RyaW5nLCB0aW1lb3V0OiBudW1iZXIsIGJlYXJlcjogc3RyaW5nLCBzaWQ6IHN0cmluZyk6IFByb21pc2U8V2ViU29ja2V0PiB7XG4gICAgICAgIGNvbnN0IGZ1bGxfaG9zdF91cmwgPSBuZXcgVVJMKGhvc3QpO1xuICAgICAgICBmdWxsX2hvc3RfdXJsLnNlYXJjaFBhcmFtcy5zZXQoXCJhdXRob3JpemF0aW9uXCIsIGBCZWFyZXIgJHtiZWFyZXJ9YCk7XG4gICAgICAgIGZ1bGxfaG9zdF91cmwuc2VhcmNoUGFyYW1zLnNldChcIngtY3J5by1zaWRcIiwgc2lkKTtcbiAgICAgICAgY29uc3Qgc2NrID0gbmV3IFdlYlNvY2tldChmdWxsX2hvc3RfdXJsKTtcbiAgICAgICAgc2NrLmJpbmFyeVR5cGUgPSBcImFycmF5YnVmZmVyXCI7XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlPFdlYlNvY2tldD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKHNjay5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTilcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgQ29ubmVjdGlvbiB0aW1lb3V0IG9mICR7dGltZW91dH0gbXMgcmVhY2hlZCFgKSk7XG4gICAgICAgICAgICB9LCB0aW1lb3V0KVxuICAgICAgICAgICAgc2NrLmFkZEV2ZW50TGlzdGVuZXIoXCJvcGVuXCIsICgpID0+IHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKHNjayk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgc2NrLmFkZEV2ZW50TGlzdGVuZXIoXCJlcnJvclwiLCAoZXJyKSA9PiB7XG4gICAgICAgICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgRXJyb3IgZHVyaW5nIHNlc3Npb24gaW5pdGlhbGlzYXRpb24hYCwge2NhdXNlOiBlcnJ9KSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICBwdWJsaWMgc3RhdGljIGFzeW5jIENvbm5lY3QoaG9zdDogc3RyaW5nLCBiZWFyZXI6IHN0cmluZywgdXNlX2NhbGU6IGJvb2xlYW4gPSB0cnVlLCB0aW1lb3V0OiBudW1iZXIgPSA1MDAwKTogUHJvbWlzZTxDcnlvQ2xpZW50V2Vic29ja2V0U2Vzc2lvbj4ge1xuICAgICAgICBjb25zdCBzaWQ6IFVVSUQgPSBjcnlwdG8ucmFuZG9tVVVJRCgpO1xuXG4gICAgICAgIGNvbnN0IHNvY2tldCA9IGF3YWl0IENyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uLkNvbnN0cnVjdFNvY2tldChob3N0LCB0aW1lb3V0LCBiZWFyZXIsIHNpZCk7XG4gICAgICAgIHJldHVybiBuZXcgQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24oaG9zdCwgc2lkLCBzb2NrZXQsIHRpbWVvdXQsIGJlYXJlciwgdXNlX2NhbGUpO1xuICAgIH1cblxuICAgIC8qXG4gICAgKiBIYW5kbGUgYW4gb3V0Z29pbmcgYmluYXJ5IG1lc3NhZ2VcbiAgICAqICovXG4gICAgcHJpdmF0ZSBhc3luYyBIYW5kbGVPdXRnb2luZ0JpbmFyeU1lc3NhZ2Uob3V0Z29pbmdfbWVzc2FnZTogQ3J5b0J1ZmZlcik6IFByb21pc2U8dm9pZD4ge1xuICAgICAgICBpZiAodGhpcy5zb2NrZXQucmVhZHlTdGF0ZSA9PT0gV2ViU29ja2V0LkNMT1NJTkcgfHwgdGhpcy5zb2NrZXQucmVhZHlTdGF0ZSA9PT0gV2ViU29ja2V0LkNMT1NFRClcbiAgICAgICAgICAgIHJldHVybjtcblxuICAgICAgICAvL0NyZWF0ZSBhIHBlbmRpbmcgbWVzc2FnZSB3aXRoIGEgbmV3IGFjayBudW1iZXIgYW5kIHF1ZXVlIGl0IGZvciBhY2tub3dsZWRnZW1lbnQgYnkgdGhlIHNlcnZlclxuICAgICAgICBjb25zdCB0eXBlID0gQ3J5b0ZyYW1lRm9ybWF0dGVyLkdldFR5cGUob3V0Z29pbmdfbWVzc2FnZSk7XG4gICAgICAgIGlmICh0eXBlID09PSBCaW5hcnlNZXNzYWdlVHlwZS5VVEY4REFUQSB8fCB0eXBlID09PSBCaW5hcnlNZXNzYWdlVHlwZS5CSU5BUllEQVRBKSB7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlX2FjayA9IENyeW9GcmFtZUZvcm1hdHRlci5HZXRBY2sob3V0Z29pbmdfbWVzc2FnZSk7XG4gICAgICAgICAgICB0aGlzLnNlcnZlcl9hY2tfdHJhY2tlci5UcmFjayhtZXNzYWdlX2Fjaywge1xuICAgICAgICAgICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgICAgICAgICAgICBtZXNzYWdlOiBvdXRnb2luZ19tZXNzYWdlXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vU2VuZCB0aGUgbWVzc2FnZSBidWZmZXIgdG8gdGhlIHNlcnZlclxuICAgICAgICBpZiAoIXRoaXMuc29ja2V0KVxuICAgICAgICAgICAgcmV0dXJuO1xuXG4gICAgICAgIGxldCBtZXNzYWdlID0gb3V0Z29pbmdfbWVzc2FnZTtcbiAgICAgICAgaWYgKHRoaXMudXNlX2NhbGUgJiYgdGhpcy5zZWN1cmUpIHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBhd2FpdCB0aGlzLmNyeXB0byEuZW5jcnlwdChvdXRnb2luZ19tZXNzYWdlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0aGlzLnNvY2tldC5zZW5kKG1lc3NhZ2UuYnVmZmVyKTtcbiAgICAgICAgfSBjYXRjaCAoZXgpIHtcbiAgICAgICAgICAgIGlmIChleCBpbnN0YW5jZW9mIEVycm9yKVxuICAgICAgICAgICAgICAgIHRoaXMuSGFuZGxlRXJyb3IoZXgpLnRoZW4ociA9PiBudWxsKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMubG9nKGBTZW50ICR7Q3J5b0ZyYW1lSW5zcGVjdG9yLkluc3BlY3Qob3V0Z29pbmdfbWVzc2FnZSl9IHRvIHNlcnZlci5gKTtcblxuXG4gICAgfVxuXG4gICAgLypcbiAgICAqIFJlc3BvbmQgdG8gUE9ORyBmcmFtZXMgd2l0aCBQSU5HIGFuZCB2aWNlIHZlcnNhXG4gICAgKiAqL1xuICAgIHByaXZhdGUgYXN5bmMgSGFuZGxlUGluZ1BvbmdNZXNzYWdlKG1lc3NhZ2U6IENyeW9CdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgY29uc3QgZGVjb2RlZFBpbmdQb25nTWVzc2FnZSA9IHRoaXMucGluZ19wb25nX2Zvcm1hdHRlclxuICAgICAgICAgICAgLkRlc2VyaWFsaXplKG1lc3NhZ2UpO1xuXG4gICAgICAgIGNvbnN0IHBpbmdfcG9uZ01lc3NhZ2UgPSB0aGlzLnBpbmdfcG9uZ19mb3JtYXR0ZXJcbiAgICAgICAgICAgIC5TZXJpYWxpemUodGhpcy5zaWQsIGRlY29kZWRQaW5nUG9uZ01lc3NhZ2UuYWNrLCBkZWNvZGVkUGluZ1BvbmdNZXNzYWdlLnBheWxvYWQgPT09IFwicG9uZ1wiID8gXCJwaW5nXCIgOiBcInBvbmdcIik7XG5cbiAgICAgICAgYXdhaXQgdGhpcy5IYW5kbGVPdXRnb2luZ0JpbmFyeU1lc3NhZ2UocGluZ19wb25nTWVzc2FnZSk7XG4gICAgfVxuXG4gICAgLypcbiAgICAqIEhhbmRsaW5nIG9mIGJpbmFyeSBlcnJvciBtZXNzYWdlcyBmcm9tIHRoZSBzZXJ2ZXIsIGN1cnJlbnRseSBqdXN0IGxvZyBpdFxuICAgICogKi9cbiAgICBwcml2YXRlIGFzeW5jIEhhbmRsZUVycm9yTWVzc2FnZShtZXNzYWdlOiBDcnlvQnVmZmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgICAgIGNvbnN0IGRlY29kZWRFcnJvck1lc3NhZ2UgPSB0aGlzLmVycm9yX2Zvcm1hdHRlclxuICAgICAgICAgICAgLkRlc2VyaWFsaXplKG1lc3NhZ2UpO1xuXG4gICAgICAgIHRoaXMubG9nKGRlY29kZWRFcnJvck1lc3NhZ2UucGF5bG9hZCk7XG4gICAgfVxuXG4gICAgLypcbiAgICAqIExvY2FsbHkgQUNLIHRoZSBwZW5kaW5nIG1lc3NhZ2UgaWYgaXQgbWF0Y2hlcyB0aGUgc2VydmVyJ3MgQUNLXG4gICAgKiAqL1xuICAgIHByaXZhdGUgYXN5bmMgSGFuZGxlQWNrTWVzc2FnZShtZXNzYWdlOiBCdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgY29uc3QgZGVjb2RlZEFja01lc3NhZ2UgPSB0aGlzLmFja19mb3JtYXR0ZXJcbiAgICAgICAgICAgIC5EZXNlcmlhbGl6ZShtZXNzYWdlKTtcbiAgICAgICAgY29uc3QgYWNrX2lkID0gZGVjb2RlZEFja01lc3NhZ2UuYWNrO1xuXG4gICAgICAgIGNvbnN0IGZvdW5kX21lc3NhZ2UgPSB0aGlzLnNlcnZlcl9hY2tfdHJhY2tlci5Db25maXJtKGFja19pZCk7XG5cbiAgICAgICAgaWYgKCFmb3VuZF9tZXNzYWdlKSB7XG4gICAgICAgICAgICB0aGlzLmxvZyhgR290IHVua25vd24gYWNrX2lkICR7YWNrX2lkfSBmcm9tIHNlcnZlci5gKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMubWVzc2FnZXNfcGVuZGluZ19zZXJ2ZXJfYWNrLmRlbGV0ZShhY2tfaWQpO1xuICAgICAgICB0aGlzLmxvZyhgR290IEFDSyAke2Fja19pZH0gZnJvbSBzZXJ2ZXIuYCk7XG4gICAgfVxuXG4gICAgLypcbiAgICAqIEV4dHJhY3QgcGF5bG9hZCBmcm9tIHRoZSBiaW5hcnkgbWVzc2FnZSBhbmQgZW1pdCB0aGUgbWVzc2FnZSBldmVudCB3aXRoIHRoZSB1dGY4IHBheWxvYWRcbiAgICAqICovXG4gICAgcHJpdmF0ZSBhc3luYyBIYW5kbGVVVEY4RGF0YU1lc3NhZ2UobWVzc2FnZTogQnVmZmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgICAgIGNvbnN0IGRlY29kZWREYXRhTWVzc2FnZSA9IHRoaXMudXRmOF9mb3JtYXR0ZXJcbiAgICAgICAgICAgIC5EZXNlcmlhbGl6ZShtZXNzYWdlKTtcblxuICAgICAgICBjb25zdCBwYXlsb2FkID0gZGVjb2RlZERhdGFNZXNzYWdlLnBheWxvYWQ7XG5cbiAgICAgICAgY29uc3QgZW5jb2RlZEFja01lc3NhZ2UgPSB0aGlzLmFja19mb3JtYXR0ZXJcbiAgICAgICAgICAgIC5TZXJpYWxpemUodGhpcy5zaWQsIGRlY29kZWREYXRhTWVzc2FnZS5hY2spO1xuXG4gICAgICAgIGF3YWl0IHRoaXMuSGFuZGxlT3V0Z29pbmdCaW5hcnlNZXNzYWdlKGVuY29kZWRBY2tNZXNzYWdlKTtcbiAgICAgICAgdGhpcy5lbWl0KFwibWVzc2FnZS11dGY4XCIsIHBheWxvYWQpO1xuICAgIH1cblxuICAgIC8qXG4gICAgKiBFeHRyYWN0IHBheWxvYWQgZnJvbSB0aGUgYmluYXJ5IG1lc3NhZ2UgYW5kIGVtaXQgdGhlIG1lc3NhZ2UgZXZlbnQgd2l0aCB0aGUgYmluYXJ5IHBheWxvYWRcbiAgICAqICovXG4gICAgcHJpdmF0ZSBhc3luYyBIYW5kbGVCaW5hcnlEYXRhTWVzc2FnZShtZXNzYWdlOiBCdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgY29uc3QgZGVjb2RlZERhdGFNZXNzYWdlID0gdGhpcy5iaW5hcnlfZm9ybWF0dGVyXG4gICAgICAgICAgICAuRGVzZXJpYWxpemUobWVzc2FnZSk7XG5cbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGRlY29kZWREYXRhTWVzc2FnZS5wYXlsb2FkO1xuXG4gICAgICAgIGNvbnN0IGVuY29kZWRBY2tNZXNzYWdlID0gdGhpcy5hY2tfZm9ybWF0dGVyXG4gICAgICAgICAgICAuU2VyaWFsaXplKHRoaXMuc2lkLCBkZWNvZGVkRGF0YU1lc3NhZ2UuYWNrKTtcblxuICAgICAgICBhd2FpdCB0aGlzLkhhbmRsZU91dGdvaW5nQmluYXJ5TWVzc2FnZShlbmNvZGVkQWNrTWVzc2FnZSk7XG4gICAgICAgIHRoaXMuZW1pdChcIm1lc3NhZ2UtYmluYXJ5XCIsIHBheWxvYWQpO1xuICAgIH1cblxuICAgIHByaXZhdGUgYXN5bmMgSGFuZGxlRXJyb3IoZXJyOiBFcnJvcikge1xuICAgICAgICB0aGlzLmxvZyhgJHtlcnIubmFtZX0gRXhjZXB0aW9uIGluIENyeW9Tb2NrZXQ6ICR7ZXJyLm1lc3NhZ2V9YCk7XG4gICAgICAgIHRoaXMuc29ja2V0LmNsb3NlKENsb3NlQ29kZS5DTE9TRV9TRVJWRVJfRVJST1IsIGBDcnlvU29ja2V0ICR7dGhpcy5zaWR9IHdhcyBjbG9zZWQgZHVlIHRvIGFuIGVycm9yLmApO1xuICAgIH1cblxuICAgIHByaXZhdGUgVHJhbnNsYXRlQ2xvc2VDb2RlKGNvZGU6IG51bWJlcik6IHN0cmluZyB7XG4gICAgICAgIHN3aXRjaCAoY29kZSBhcyBDbG9zZUNvZGUpIHtcbiAgICAgICAgICAgIGNhc2UgQ2xvc2VDb2RlLkNMT1NFX0dSQUNFRlVMOlxuICAgICAgICAgICAgICAgIHJldHVybiBcIkNvbm5lY3Rpb24gY2xvc2VkIG5vcm1hbGx5LlwiO1xuICAgICAgICAgICAgY2FzZSBDbG9zZUNvZGUuQ0xPU0VfQ0xJRU5UX0VSUk9SOlxuICAgICAgICAgICAgICAgIHJldHVybiBcIkNvbm5lY3Rpb24gY2xvc2VkIGR1ZSB0byBhIGNsaWVudCBlcnJvci5cIjtcbiAgICAgICAgICAgIGNhc2UgQ2xvc2VDb2RlLkNMT1NFX1NFUlZFUl9FUlJPUjpcbiAgICAgICAgICAgICAgICByZXR1cm4gXCJDb25uZWN0aW9uIGNsb3NlZCBkdWUgdG8gYSBzZXJ2ZXIgZXJyb3IuXCI7XG4gICAgICAgICAgICBjYXNlIENsb3NlQ29kZS5DTE9TRV9DQUxFX01JU01BVENIOlxuICAgICAgICAgICAgICAgIHJldHVybiBcIkNvbm5lY3Rpb24gY2xvc2VkIGR1ZSB0byBhIG1pc21hdGNoIGluIGNsaWVudC9zZXJ2ZXIgQ0FMRSBjb25maWd1cmF0aW9uLlwiO1xuICAgICAgICAgICAgY2FzZSBDbG9zZUNvZGUuQ0xPU0VfQ0FMRV9IQU5EU0hBS0U6XG4gICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29ubmVjdGlvbiBjbG9zZWQgZHVlIHRvIGFuIGVycm9yIGluIHRoZSBDQUxFIGhhbmRzaGFrZS5cIjtcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIFwiVW5zcGVjaWZpZWQgY2F1c2UgZm9yIGNvbm5lY3Rpb24gY2xvc3VyZS5cIlxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBhc3luYyBIYW5kbGVDbG9zZShjb2RlOiBudW1iZXIsIHJlYXNvbjogQnVmZmVyKSB7XG4gICAgICAgIGNvbnNvbGUud2FybihgV2Vic29ja2V0IHdhcyBjbG9zZWQuIENvZGU9JHtjb2RlfSAoJHt0aGlzLlRyYW5zbGF0ZUNsb3NlQ29kZShjb2RlKX0pLCByZWFzb249JHtyZWFzb24udG9TdHJpbmcoXCJ1dGY4XCIpfS5gKTtcblxuICAgICAgICBpZiAoY29kZSAhPT0gQ2xvc2VDb2RlLkNMT1NFX1NFUlZFUl9FUlJPUilcbiAgICAgICAgICAgIHJldHVybjtcblxuICAgICAgICBsZXQgY3VycmVudF9hdHRlbXB0ID0gMDtcbiAgICAgICAgbGV0IGJhY2tfb2ZmX2RlbGF5ID0gNTAwMDtcblxuICAgICAgICAvL0lmIHRoZSBjb25uZWN0aW9uIHdhcyBub3Qgbm9ybWFsbHkgY2xvc2VkLCB0cnkgdG8gcmVjb25uZWN0XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoYEFibm9ybWFsIHRlcm1pbmF0aW9uIG9mIFdlYnNvY2tldCBjb25uZWN0aW9uLCBhdHRlbXB0aW5nIHRvIHJlY29ubmVjdC4uLmApO1xuICAgICAgICAvLy9AdHMtZXhwZWN0LWVycm9yXG4gICAgICAgIHRoaXMuc29ja2V0ID0gbnVsbDtcblxuICAgICAgICB0aGlzLmVtaXQoXCJkaXNjb25uZWN0ZWRcIiwgdW5kZWZpbmVkKVxuICAgICAgICB3aGlsZSAoY3VycmVudF9hdHRlbXB0IDwgNSkge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICB0aGlzLnNvY2tldCA9IGF3YWl0IENyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uLkNvbnN0cnVjdFNvY2tldCh0aGlzLmhvc3QsIHRoaXMudGltZW91dCwgdGhpcy5iZWFyZXIsIHRoaXMuc2lkKTtcbiAgICAgICAgICAgICAgICB0aGlzLkF0dGFjaExpc3RlbmVyc1RvU29ja2V0KHRoaXMuc29ja2V0KTtcblxuICAgICAgICAgICAgICAgIHRoaXMuZW1pdChcInJlY29ubmVjdGVkXCIsIHVuZGVmaW5lZCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfSBjYXRjaCAoZXgpIHtcbiAgICAgICAgICAgICAgICBpZiAoZXggaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICAgICAgICAgICAgICAvLy9AdHMtZXhwZWN0LWVycm9yXG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGVycm9yQ29kZSA9IGV4LmNhdXNlPy5lcnJvcj8uY29kZSBhcyBzdHJpbmc7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihgVW5hYmxlIHRvIHJlY29ubmVjdCB0byAnJHt0aGlzLmhvc3R9Jy4gRXJyb3IgY29kZTogJyR7ZXJyb3JDb2RlfScuIFJldHJ5IGF0dGVtcHQgaW4gJHtiYWNrX29mZl9kZWxheX0gbXMuIEF0dGVtcHQgJHtjdXJyZW50X2F0dGVtcHQrK30gLyA1YCk7XG4gICAgICAgICAgICAgICAgICAgIGF3YWl0IG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiBzZXRUaW1lb3V0KHJlc29sdmUsIGJhY2tfb2ZmX2RlbGF5KSk7XG4gICAgICAgICAgICAgICAgICAgIGJhY2tfb2ZmX2RlbGF5ICs9IGN1cnJlbnRfYXR0ZW1wdCAqIDEwMDA7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgY29uc29sZS5lcnJvcihgR2F2ZSB1cCBvbiByZWNvbm5lY3RpbmcgdG8gJyR7dGhpcy5ob3N0fSdgKTtcblxuICAgICAgICBpZiAodGhpcy5zb2NrZXQpXG4gICAgICAgICAgICB0aGlzLnNvY2tldC5jbG9zZSgpO1xuXG4gICAgICAgIHRoaXMuZW1pdChcImNsb3NlZFwiLCBbY29kZSwgcmVhc29uLnRvU3RyaW5nKFwidXRmOFwiKV0pO1xuICAgIH1cblxuICAgIC8qXG4gICAgKiBTZW5kIGFuIHV0ZjggbWVzc2FnZSB0byB0aGUgc2VydmVyXG4gICAgKiAqL1xuICAgIHB1YmxpYyBhc3luYyBTZW5kVVRGOChtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgY29uc3QgbmV3X2Fja19pZCA9IHRoaXMuY3VycmVudF9hY2srKztcblxuICAgICAgICBjb25zdCBmb3JtYXR0ZWRfbWVzc2FnZSA9IENyeW9GcmFtZUZvcm1hdHRlclxuICAgICAgICAgICAgLkdldEZvcm1hdHRlcihcInV0ZjhkYXRhXCIpXG4gICAgICAgICAgICAuU2VyaWFsaXplKHRoaXMuc2lkLCBuZXdfYWNrX2lkLCBtZXNzYWdlKTtcblxuICAgICAgICBhd2FpdCB0aGlzLkhhbmRsZU91dGdvaW5nQmluYXJ5TWVzc2FnZShmb3JtYXR0ZWRfbWVzc2FnZSk7XG4gICAgfVxuXG4gICAgLypcbiAgICAqIFNlbmQgYSBiaW5hcnkgbWVzc2FnZSB0byB0aGUgc2VydmVyXG4gICAgKiAqL1xuICAgIHB1YmxpYyBhc3luYyBTZW5kQmluYXJ5KG1lc3NhZ2U6IENyeW9CdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgY29uc3QgbmV3X2Fja19pZCA9IHRoaXMuY3VycmVudF9hY2srKztcblxuICAgICAgICBjb25zdCBmb3JtYXR0ZWRfbWVzc2FnZSA9IENyeW9GcmFtZUZvcm1hdHRlclxuICAgICAgICAgICAgLkdldEZvcm1hdHRlcihcImJpbmFyeWRhdGFcIilcbiAgICAgICAgICAgIC5TZXJpYWxpemUodGhpcy5zaWQsIG5ld19hY2tfaWQsIG1lc3NhZ2UpO1xuXG4gICAgICAgIGF3YWl0IHRoaXMuSGFuZGxlT3V0Z29pbmdCaW5hcnlNZXNzYWdlKGZvcm1hdHRlZF9tZXNzYWdlKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgQ2xvc2UoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuRGVzdHJveShDbG9zZUNvZGUuQ0xPU0VfR1JBQ0VGVUwsIFwiQ2xpZW50IGZpbmlzaGVkLlwiKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgZ2V0IHNlY3VyZSgpOiBib29sZWFuIHtcbiAgICAgICAgcmV0dXJuIHRoaXMudXNlX2NhbGUgJiYgdGhpcy5jcnlwdG8gIT09IG51bGw7XG4gICAgfVxuXG4gICAgcHVibGljIGdldCBzZXNzaW9uX2lkKCk6IFVVSUQge1xuICAgICAgICByZXR1cm4gdGhpcy5zaWQ7XG4gICAgfVxuXG4gICAgcHVibGljIERlc3Ryb3koY29kZTogbnVtYmVyID0gMTAwMCwgbWVzc2FnZTogc3RyaW5nID0gXCJcIikge1xuICAgICAgICB0aGlzLmxvZyhgVGVhcmRvd24gb2Ygc2Vzc2lvbi4gQ29kZT0ke2NvZGV9LCByZWFzb249JHttZXNzYWdlfWApO1xuICAgICAgICB0aGlzLnNvY2tldC5jbG9zZShjb2RlLCBtZXNzYWdlKTtcbiAgICB9XG59XG4iLCAiaW1wb3J0IHtDcnlvQ2xpZW50V2Vic29ja2V0U2Vzc2lvbn0gZnJvbSBcIi4vQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24vQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24uanNcIjtcblxuLyoqXG4gKiBDcmVhdGUgYSBDcnlvIGNsaWVudFxuICogQHBhcmFtIGhvc3QgLSBUaGUgc2VydmVyIHRvIGNvbm5lY3QgdG9cbiAqIEBwYXJhbSBiZWFyZXIgLSBUaGUgQmVhcmVyIHRva2VuIGZvciB0aGUgc2VydmVyIHRvIHZhbGlkYXRlXG4gKiBAcGFyYW0gdXNlX2NhbGUgLSBJZiBjQUxFIChhcHBsaWNhdGlvbiBsYXllciBlbmNyeXB0aW9uKSBzaG91bGQgYmUgZW5hYmxlZFxuICogQHBhcmFtIHRpbWVvdXQgLSBIb3cgbG9uZyB0byB3YWl0IHVudGlsIHRoZSBjbGllbnQgc3RvcHMgZXN0YWJsaXNoaW5nIGEgY29ubmVjdGlvblxuICogKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcnlvKGhvc3Q6IHN0cmluZywgYmVhcmVyOiBzdHJpbmcsIHVzZV9jYWxlOiBib29sZWFuLCB0aW1lb3V0OiBudW1iZXIgPSA1MDAwKSB7XG4gICAgcmV0dXJuIENyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uLkNvbm5lY3QoaG9zdCwgYmVhcmVyLCB1c2VfY2FsZSwgdGltZW91dCk7XG59IiwgImltcG9ydCB7Y3J5bywgQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb259IGZyb20gXCJjcnlvLWNsaWVudC1icm93c2VyXCJcclxuaW1wb3J0IHtDb21wb25lbnRFdmVudH0gZnJvbSBcIi4vVUkvQmFzZS9CYXNlQ29tcG9uZW50L0Jhc2VDb21wb25lbnQuanNcIjtcclxuXHJcbnR5cGUgSW5jb21pbmdNZXNzYWdlID0ge1xyXG4gICAgaHRtbDogc3RyaW5nO1xyXG4gICAgdGFyZ2V0OiBzdHJpbmc7XHJcbiAgICBldmVudHM6IENvbXBvbmVudEV2ZW50O1xyXG59XHJcblxyXG5kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKFwiRE9NQ29udGVudExvYWRlZFwiLCBhc3luYyAoKSA9PiB7XHJcbiAgICBjb25zdCBjbGllbnQgPSBhd2FpdCBjcnlvKFwid3M6Ly9sb2NhbGhvc3Q6ODA4MFwiLCBcInRlc3RcIiwgZmFsc2UpO1xyXG5cclxuICAgIGNsaWVudC5vbihcImNvbm5lY3RlZFwiLCAoKSA9PiB7XHJcbiAgICAgICAgY29uc29sZS5pbmZvKFwiQ29ubmVjdGVkIHRvIGJhY2tlbmQuXCIpO1xyXG4gICAgfSk7XHJcblxyXG4gICAgY2xpZW50Lm9uKFwicmVjb25uZWN0ZWRcIiwgYXN5bmMgKCkgPT4ge1xyXG4gICAgICAgIGNvbnNvbGUuaW5mbyhcIlJlY29ubmVjdGVkIHRvIGJhY2tlbmQuXCIpO1xyXG4gICAgfSk7XHJcblxyXG4gICAgY2xpZW50Lm9uKFwiZGlzY29ubmVjdGVkXCIsIGFzeW5jICgpID0+IHtcclxuICAgICAgICBjb25zb2xlLmluZm8oXCJEaXNjb25uZWN0ZWQgZnJvbSBiYWNrZW5kLlwiKTtcclxuICAgIH0pO1xyXG5cclxuICAgIGNsaWVudC5vbihcImNsb3NlZFwiLCBhc3luYyAoKSA9PiB7XHJcbiAgICAgICAgY29uc29sZS5pbmZvKFwiQmFja2VuZCBjb25uZWN0aW9uIGNsb3NlZC5cIik7XHJcbiAgICB9KTtcclxuXHJcbiAgICBjbGllbnQub24oXCJtZXNzYWdlLXV0ZjhcIiwgKG1lc3NhZ2UpID0+IHtcclxuICAgICAgICBjb25zdCB7aHRtbCwgdGFyZ2V0LCBldmVudHN9ID0gSlNPTi5wYXJzZShtZXNzYWdlKSBhcyBJbmNvbWluZ01lc3NhZ2U7XHJcbiAgICAgICAgY29uc29sZS5pbmZvKGBHb3QgVUkgZGF0YSBmcm9tIHRoZSBiYWNrZW5kLiBSZW5kZXJpbmcgJyR7dGFyZ2V0fSdgKVxyXG4gICAgICAgIGNvbnN0IGRvbUVsZW1lbnQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKGBbZGF0YS10YXJnZXQ9JHt0YXJnZXR9XWApO1xyXG4gICAgICAgIGlmICghZG9tRWxlbWVudCkge1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVsZW1lbnQgd2l0aCBkYXRhLXRhcmdldCAnJHt0YXJnZXR9JyBub3QgZm91bmQgaW4gRE9NIWApO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgLy9VcGRhdGUgdGhlIGZvdW5kIGVsZW1lbnRcclxuICAgICAgICBkb21FbGVtZW50Lm91dGVySFRNTCA9IGh0bWw7XHJcblxyXG4gICAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoXCJbZGF0YS1ldmVudF1cIilcclxuICAgICAgICAgICAgLmZvckVhY2goKGVsZW1lbnQpID0+IHtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50VHlwZXMgPSBlbGVtZW50LmdldEF0dHJpYnV0ZShcImRhdGEtZXZlbnRcIik7XHJcbiAgICAgICAgICAgICAgICBjb25zdCBldmVudFRhcmdldCA9IGVsZW1lbnQuZ2V0QXR0cmlidXRlKFwiZGF0YS10YXJnZXRcIik7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudFR5cGVzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS53YXJuKGBFbGVtZW50IHdpdGggZGF0YS10YXJnZXQgJyR7ZWxlbWVudC5pZH0nIGVpdGhlciBoYXMgbm8gZGF0YS1ldmVudCBwcm9wZXJ0eSBvciBpdCBoYXMgbm8gdmFsdWUuYCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmICghZXZlbnRUYXJnZXQpIHtcclxuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oYEVsZW1lbnQgd2l0aCBkYXRhLXRhcmdldCAnJHtlbGVtZW50LmlkfScgZWl0aGVyIGhhcyBubyBkYXRhLXRhcmdldCBwcm9wZXJ0eSBvciBpdCBoYXMgbm8gdmFsdWUuYCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8qXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5pbmZvKGBSZWdpc3RlcmVkIENyeW9VSSBldmVudCAnJHtldmVudFR5cGVzfScgd2l0aCB0YXJnZXQgJyR7ZXZlbnRUYXJnZXR9J2ApO1xyXG4gICAgICAgICAgICAgICAgKi9cclxuICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50czogc3RyaW5nW10gPSBldmVudFR5cGVzLnNwbGl0KFwiLFwiKTtcclxuICAgICAgICAgICAgICAgIGV2ZW50cy5mb3JFYWNoKGV2ZW50VHlwZSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgZWxlbWVudC5hZGRFdmVudExpc3RlbmVyKGV2ZW50VHlwZSwgKGUpID0+IHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZS5zdG9wSW1tZWRpYXRlUHJvcGFnYXRpb24oKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGRhdGE6IFJlY29yZDxzdHJpbmcsIHN0cmluZyB8IHVuZGVmaW5lZD4gPSB7fTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlLnRhcmdldCBpbnN0YW5jZW9mIEhUTUxGb3JtRWxlbWVudClcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhdGEgPSBPYmplY3QuZnJvbUVudHJpZXMoKG5ldyBGb3JtRGF0YShlLnRhcmdldCBhcyBIVE1MRm9ybUVsZW1lbnQpIGFzIHVua25vd24gYXMgSXRlcmFibGU8cmVhZG9ubHkgW1Byb3BlcnR5S2V5LCBzdHJpbmcgfCB1bmRlZmluZWRdPikpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXRhID0gT2JqZWN0LmZyb21FbnRyaWVzKE9iamVjdC5lbnRyaWVzKCgoZWxlbWVudCBhcyBIVE1MRWxlbWVudCk/LmRhdGFzZXQgfHwge30pKSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAvL1N0cmlwIGRhdGEtZXZlbnQgYW5kIGRhdGEtdGFyZ2V0XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBkYXRhPy5ldmVudDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIGRhdGE/LnRhcmdldDtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudC5TZW5kVVRGOChKU09OLnN0cmluZ2lmeSh7dHlwZTogZXZlbnRUeXBlLCB0YXJnZXQ6IGV2ZW50VGFyZ2V0LCBkYXRhfSkpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIH0pO1xy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UUFBUSxhQUFhLFlBQVk7QUFDcEQsWUFBTSxjQUFjLFFBQVEsYUFBYSxhQUFhO0FBRXRELFVBQUksQ0FBQyxZQUFZO0FBQ2IsZ0JBQVEsS0FBSyw2QkFBNkIsUUFBUSxFQUFFLHlEQUF5RDtBQUM3RztBQUFBLE1BQ0o7QUFFQSxVQUFJLENBQUMsYUFBYTtBQUNkLGdCQUFRLEtBQUssNkJBQTZCLFFBQVEsRUFBRSwwREFBMEQ7QUFDOUc7QUFBQSxNQUNKO0FBS0EsWUFBTUMsVUFBbUIsV0FBVyxNQUFNLEdBQUc7QUFDN0MsTUFBQUEsUUFBTyxRQUFRLGVBQWE7QUFDeEIsZ0JBQVEsaUJBQWlCLFdBQVcsQ0FBQyxNQUFNO0FBQ3ZDLFlBQUUseUJBQXlCO0FBQzNCLFlBQUUsZUFBZTtBQUVqQixjQUFJLE9BQTJDLENBQUM7QUFFaEQsY0FBSSxFQUFFLGtCQUFrQjtBQUNwQixtQkFBTyxPQUFPLFlBQWEsSUFBSSxTQUFTLEVBQUUsTUFBeUIsQ0FBcUU7QUFBQTtBQUV4SSxtQkFBTyxPQUFPLFlBQVksT0FBTyxRQUFVLFNBQXlCLFdBQVcsQ0FBQyxDQUFFLENBQUM7QUFHdkYsaUJBQU8sTUFBTTtBQUNiLGlCQUFPLE1BQU07QUFFYixpQkFBTyxTQUFTLEtBQUssVUFBVSxFQUFDLE1BQU0sV0FBVyxRQUFRLGFBQWEsS0FBSSxDQUFDLENBQUM7QUFDNUU7QUFBQSxRQUNKLENBQUM7QUFBQSxNQUNMLENBQUM7QUFBQSxJQUNMLENBQUM7QUFBQSxFQUNULENBQUM7QUFDTCxDQUFDOyIsCiAgIm5hbWVzIjogWyJBY2tUcmFja2VyIiwgImFjayIsICJtZXNzYWdlIiwgIm1heWJlX2FjayIsICJDcnlvQnVmZmVyIiwgIl9DcnlvQnVmZmVyIiwgImJ1ZmZlciIsICJsZW5ndGgiLCAiaW5wdXQiLCAiZW5jb2RpbmciLCAiZGF0YSIsICJpIiwgImJ1ZmZlcnMiLCAibGVuZ3RoX3RvdGFsIiwgImFjYyIsICJ2IiwgInJlc3VsdCIsICJvZmZzZXQiLCAiYnVmIiwgInZhbHVlIiwgInRleHQiLCAiYnl0ZSIsICJzdGFydCIsICJlbmQiLCAidGFyZ2V0IiwgInRhcmdldF9zdGFydCIsICJHdWFyZEVycm9yIiwgIl9HdWFyZEVycm9yIiwgInBNZXNzYWdlIiwgIkd1YXJkIiwgIl9HdWFyZCIsICJwYXJhbSIsICJleHByIiwgIkNyeW9CdWZmZXJVdGlsIiwgInV1aWR2NF9wMSIsICJ1dWlkdjRfcDIiLCAidXVpZHY0X3AzIiwgInV1aWR2NF9wNCIsICJ1dWlkdjRfcDUiLCAic2lkIiwgIkFja0ZyYW1lRm9ybWF0dGVyIiwgInR5cGUiLCAicGF5bG9hZCIsICJtc2dfYnVmIiwgIlBpbmdQb25nRnJhbWVGb3JtYXR0ZXIiLCAiVVRGOEZyYW1lRm9ybWF0dGVyIiwgIkJpbmFyeUZyYW1lRm9ybWF0dGVyIiwgInBheWxvYWRfbGVuZ3RoIiwgIkVycm9yRnJhbWVGb3JtYXR0ZXIiLCAiU2VydmVySGVsbG9GcmFtZUZvcm1hdHRlciIsICJDbGllbnRIZWxsb0ZyYW1lRm9ybWF0dGVyIiwgIkhhbmRzaGFrZURvbmVGcmFtZUZvcm1hdHRlciIsICJDcnlvRnJhbWVGb3JtYXR0ZXIiLCAidHlwZVRvU3RyaW5nTWFwIiwgIkNyeW9GcmFtZUluc3BlY3RvciIsICJ0eXBlX3N0ciIsICJDcmVhdGVEZWJ1Z0xvZ2dlciIsICJzZWN0aW9uIiwgIm1zZyIsICJwYXJhbXMiLCAibWV0aG9kX2NsZWFuZWQiLCAibWV0aG9kIiwgInBvc2l0aW9uIiwgIkNyeW9FdmVudEVtaXR0ZXIiLCAibGlzdGVuZXIiLCAiZSIsICJpbXBvcnRfa2V5IiwgInVzYWdlIiwgIm1ha2VfYWxnbyIsICJpdiIsICJDcnlvQ3J5cHRvQm94IiwgImVuY3J5cHRfa2V5IiwgImRlY3J5cHRpb25fa2V5IiwgInBsYWluIiwgImtleSIsICJlbmNyeXB0ZWQiLCAiY2lwaGVyIiwgImRhdGFfd2l0aF90YWciLCAiZGVjcnlwdGVkIiwgIkNyeW9IYW5kc2hha2VFbmdpbmUiLCAic2VuZF9wbGFpbiIsICJmb3JtYXR0ZXIiLCAibmV4dF9hY2siLCAiZXZlbnRzIiwgImV4IiwgImZyYW1lIiwgImRlY29kZWQiLCAic2VydmVyX3B1Yl9rZXkiLCAic2VjcmV0IiwgImhhc2giLCAibXlfcHViX2tleSIsICJjbGllbnRfaGVsbG8iLCAiZG9uZSIsICJDcnlvRnJhbWVSb3V0ZXIiLCAiaXNfc2VjdXJlIiwgImRlY3J5cHQiLCAiaGFuZGxlcnMiLCAibG9nIiwgInJhdyIsICJvbmNlIiwgInNvY2tldCIsICJoYW5kbGVyIiwgIndyYXBwZXIiLCAiZXYiLCAiQ3J5b0NsaWVudFdlYnNvY2tldFNlc3Npb24iLCAiX0NyeW9DbGllbnRXZWJzb2NrZXRTZXNzaW9uIiwgImhvc3QiLCAidGltZW91dCIsICJiZWFyZXIiLCAidXNlX2NhbGUiLCAiaGFuZHNoYWtlX2V2ZW50cyIsICJ0cmFuc21pdF9rZXkiLCAicmVjZWl2ZV9rZXkiLCAicmVhc29uIiwgImIiLCAiX2IiLCAiZXJyb3JfZXZlbnQiLCAiY2xvc2VfZXZlbnQiLCAiZnVsbF9ob3N0X3VybCIsICJzY2siLCAicmVzb2x2ZSIsICJyZWplY3QiLCAiZXJyIiwgIm91dGdvaW5nX21lc3NhZ2UiLCAibWVzc2FnZV9hY2siLCAiciIsICJkZWNvZGVkUGluZ1BvbmdNZXNzYWdlIiwgInBpbmdfcG9uZ01lc3NhZ2UiLCAiZGVjb2RlZEVycm9yTWVzc2FnZSIsICJhY2tfaWQiLCAiZGVjb2RlZERhdGFNZXNzYWdlIiwgImVuY29kZWRBY2tNZXNzYWdlIiwgImNvZGUiLCAiY3VycmVudF9hdHRlbXB0IiwgImJhY2tfb2ZmX2RlbGF5IiwgImVycm9yQ29kZSIsICJuZXdfYWNrX2lkIiwgImZvcm1hdHRlZF9tZXNzYWdlIiwgImNyeW8iLCAiZXZlbnRzIl0KfQo=
