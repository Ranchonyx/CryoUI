var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// node_modules/cryo-server/dist/lib/CryoWebsocketServer/CryoWebsocketServer.js
import https from "https";
import http from "node:http";
import { WebSocketServer } from "ws";
import { clearInterval as clearInterval2, setInterval as setInterval2 } from "node:timers";
import { EventEmitter as EventEmitter2 } from "node:events";

// node_modules/cryo-server/dist/lib/Common/Util/CreateDebugLogger.js
function CreateDebugLogger(section) {
  if (!process.env.DEBUG?.includes(section))
    return () => {
    };
  return (msg, ...params) => {
    const err = new Error();
    const stack = err.stack?.split("\n");
    const caller_line = stack?.[2] ?? "unknown";
    const method_cleaned = caller_line.trim().replace(/^at\s+/, "");
    const method = method_cleaned.substring(0, method_cleaned.indexOf("(") - 1);
    const position = method_cleaned.substring(method_cleaned.lastIndexOf(":") - 2, method_cleaned.length - 1);
    console.info(`PID: ${process.pid.toString().padEnd(8, " ")} ${section.padEnd(24, " ")}${(/* @__PURE__ */ new Date()).toISOString().padEnd(32, " ")} ${method.padEnd(64, " ")} ${position.padEnd(8, " ")} ${msg}`, ...params);
  };
}
__name(CreateDebugLogger, "CreateDebugLogger");

// node_modules/cryo-server/dist/lib/Common/Util/Guard.js
var GuardError = class _GuardError extends Error {
  static {
    __name(this, "GuardError");
  }
  constructor(pMessage) {
    super(pMessage);
    Error.captureStackTrace ||= () => {
    };
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, _GuardError);
    }
    Object.setPrototypeOf(this, _GuardError.prototype);
  }
};
var Guard = class _Guard {
  static {
    __name(this, "Guard");
  }
  //wenn "param" === null, throw with "message"
  static AgainstNull(param, message) {
    if (param === null)
      throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was null!`);
  }
  //Wenn "param" === "undefined", throw with "message"
  static AgainstUndefined(param, message) {
    if (param === void 0)
      throw new GuardError(message ? message : `Assertion failed, "param" (${param}) was undefined!`);
  }
  //Wenn "param" === "null" or "param" === "undefined", throw with "message"
  static AgainstNullish(param, message) {
    _Guard.AgainstUndefined(param, message);
    _Guard.AgainstNull(param, message);
  }
  //Typ von "param" als Typ "T" interpretieren
  static CastAs(param) {
    _Guard.AgainstNullish(param);
  }
  //Typ von "param" als Typ "T" interpretieren und "param" und "expr" gegen "null" und "undefined" guarden
  static CastAssert(param, expr, message) {
    _Guard.AgainstNullish(param, message);
    _Guard.AgainstNullish(expr, message);
    if (!expr)
      throw new GuardError(`Parameter assertion failed in CastAssert!`);
  }
};

// node_modules/cryo-server/dist/lib/CryoServerWebsocketSession/CryoServerWebsocketSession.js
import { EventEmitter } from "node:events";

// node_modules/cryo-server/dist/lib/Common/CryoBinaryMessage/CryoFrameFormatter.js
var BinaryMessageType;
(function(BinaryMessageType2) {
  BinaryMessageType2[BinaryMessageType2["ACK"] = 0] = "ACK";
  BinaryMessageType2[BinaryMessageType2["ERROR"] = 1] = "ERROR";
  BinaryMessageType2[BinaryMessageType2["PING_PONG"] = 2] = "PING_PONG";
  BinaryMessageType2[BinaryMessageType2["UTF8DATA"] = 3] = "UTF8DATA";
  BinaryMessageType2[BinaryMessageType2["BINARYDATA"] = 4] = "BINARYDATA";
  BinaryMessageType2[BinaryMessageType2["SERVER_HELLO"] = 5] = "SERVER_HELLO";
  BinaryMessageType2[BinaryMessageType2["CLIENT_HELLO"] = 6] = "CLIENT_HELLO";
  BinaryMessageType2[BinaryMessageType2["HANDSHAKE_DONE"] = 7] = "HANDSHAKE_DONE";
})(BinaryMessageType || (BinaryMessageType = {}));
var BufferUtil = class {
  static {
    __name(this, "BufferUtil");
  }
  static sidFromBuffer(buffer) {
    const uuidv4_p1 = buffer.subarray(0, 4).toString("hex");
    const uuidv4_p2 = buffer.subarray(4, 6).toString("hex");
    const uuidv4_p3 = buffer.subarray(6, 8).toString("hex");
    const uuidv4_p4 = buffer.subarray(8, 10).toString("hex");
    const uuidv4_p5 = buffer.subarray(10, 16).toString("hex");
    return [uuidv4_p1, uuidv4_p2, uuidv4_p3, uuidv4_p4, uuidv4_p5].join("-");
  }
  static sidToBuffer(sid) {
    return Buffer.from(sid.replaceAll("-", ""), "hex");
  }
};
var AckFrameFormatter = class {
  static {
    __name(this, "AckFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    if (type !== BinaryMessageType.ACK)
      throw new Error("Attempt to deserialize a non-ack binary message!");
    return {
      sid,
      ack,
      type
    };
  }
  // noinspection JSUnusedLocalSymbols
  Serialize(sid, ack, payload = null) {
    const msg_buf = Buffer.alloc(16 + 4 + 1);
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.ACK, 20);
    return msg_buf;
  }
};
var PingPongFrameFormatter = class {
  static {
    __name(this, "PingPongFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21).toString("utf8");
    if (type !== BinaryMessageType.PING_PONG)
      throw new Error("Attempt to deserialize a non-ping_pong binary message!");
    if (!(payload === "ping" || payload === "pong"))
      throw new Error(`Invalid payload ${payload} in ping_pong binary message!`);
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    const msg_buf = Buffer.alloc(16 + 4 + 1 + 4);
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.PING_PONG, 20);
    msg_buf.write(payload, 21);
    return msg_buf;
  }
};
var UTF8FrameFormatter = class {
  static {
    __name(this, "UTF8FrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21).toString("utf8");
    if (type !== BinaryMessageType.UTF8DATA)
      throw new Error("Attempt to deserialize a non-data utf8 message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    const msg_buf = Buffer.alloc(16 + 4 + 1 + (payload?.length || 4));
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.UTF8DATA, 20);
    msg_buf.write(payload || "null", 21);
    return msg_buf;
  }
};
var BinaryFrameFormatter = class {
  static {
    __name(this, "BinaryFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21);
    if (type !== BinaryMessageType.BINARYDATA)
      throw new Error("Attempt to deserialize a non-data binary message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    const payload_length = payload ? payload.byteLength : 4;
    const msg_buf = Buffer.alloc(16 + 4 + 1 + payload_length);
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.BINARYDATA, 20);
    msg_buf.set(payload || Buffer.from("null", "utf-8"), 21);
    return msg_buf;
  }
};
var ErrorFrameFormatter = class {
  static {
    __name(this, "ErrorFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21).toString("utf8");
    if (type !== BinaryMessageType.ERROR)
      throw new Error("Attempt to deserialize a non-error message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    const msg_buf = Buffer.alloc(16 + 4 + 1 + (payload?.length || 13));
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.ERROR, 20);
    msg_buf.write(payload || "unknown_error", 21);
    return msg_buf;
  }
};
var ServerHelloFrameFormatter = class {
  static {
    __name(this, "ServerHelloFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21);
    if (type !== BinaryMessageType.SERVER_HELLO)
      throw new Error("Attempt to deserialize a non-server_hello message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    Guard.CastAssert(payload, payload !== null, "payload was null!");
    if (payload.byteLength !== 65)
      throw new Error("Payload in ServerHelloMessage must be exactly 65 bytes!");
    const msg_buf = Buffer.alloc(16 + 4 + 1 + 65);
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.SERVER_HELLO, 20);
    msg_buf.set(payload, 21);
    return msg_buf;
  }
};
var ClientHelloFrameFormatter = class {
  static {
    __name(this, "ClientHelloFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21);
    if (type !== BinaryMessageType.CLIENT_HELLO)
      throw new Error("Attempt to deserialize a non-client_hello message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    Guard.CastAssert(payload, payload !== null, "payload was null!");
    if (payload.byteLength !== 65)
      throw new Error("Payload in ClientHelloMessage must be exactly 65 bytes!");
    const msg_buf = Buffer.alloc(16 + 4 + 1 + 65);
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.CLIENT_HELLO, 20);
    msg_buf.set(payload, 21);
    return msg_buf;
  }
};
var HandshakeDoneFrameFormatter = class {
  static {
    __name(this, "HandshakeDoneFrameFormatter");
  }
  Deserialize(value) {
    const sid = BufferUtil.sidFromBuffer(value);
    const ack = value.readUInt32BE(16);
    const type = value.readUint8(20);
    const payload = value.subarray(21).toString("utf8");
    if (type !== BinaryMessageType.HANDSHAKE_DONE)
      throw new Error("Attempt to deserialize a non-handshake_done message!");
    return {
      sid,
      ack,
      type,
      payload
    };
  }
  Serialize(sid, ack, payload) {
    const msg_buf = Buffer.alloc(16 + 4 + 1 + (payload?.length || 4));
    const sid_buf = BufferUtil.sidToBuffer(sid);
    sid_buf.copy(msg_buf, 0);
    msg_buf.writeUInt32BE(ack, 16);
    msg_buf.writeUint8(BinaryMessageType.HANDSHAKE_DONE, 20);
    msg_buf.write(payload || "null", 21);
    return msg_buf;
  }
};
var CryoFrameFormatter = class {
  static {
    __name(this, "CryoFrameFormatter");
  }
  static GetFormatter(type) {
    switch (type) {
      case "utf8data":
      case BinaryMessageType.UTF8DATA:
        return new UTF8FrameFormatter();
      case "error":
      case BinaryMessageType.ERROR:
        return new ErrorFrameFormatter();
      case "ack":
      case BinaryMessageType.ACK:
        return new AckFrameFormatter();
      case "ping_pong":
      case BinaryMessageType.PING_PONG:
        return new PingPongFrameFormatter();
      case "binarydata":
      case BinaryMessageType.BINARYDATA:
        return new BinaryFrameFormatter();
      case BinaryMessageType.SERVER_HELLO:
      case "server_hello":
        return new ServerHelloFrameFormatter();
      case BinaryMessageType.CLIENT_HELLO:
      case "client_hello":
        return new ClientHelloFrameFormatter();
      case BinaryMessageType.HANDSHAKE_DONE:
      case "handshake_done":
        return new HandshakeDoneFrameFormatter();
      default:
        throw new Error(`Binary message format for type '${type}' is not supported!`);
    }
  }
  static GetType(message) {
    const type = message.readUint8(20);
    if (type > BinaryMessageType.HANDSHAKE_DONE)
      throw new Error(`Unable to decode type from message ${message}. MAX_TYPE = 5, got ${type} !`);
    return type;
  }
  static GetAck(message) {
    return message.readUint32BE(16);
  }
  static GetSid(message) {
    return BufferUtil.sidFromBuffer(message);
  }
  static GetPayload(message, encoding = "utf8") {
    return message.subarray(21).toString(encoding);
  }
};

// node_modules/cryo-server/dist/lib/Common/CryoFrameInspector/CryoFrameInspector.js
var typeToStringMap = {
  0: "ack",
  1: "error",
  2: "ping/pong",
  3: "utf8data",
  4: "binarydata",
  5: "server_hello",
  6: "client_hello",
  7: "handshake_done"
};
var CryoFrameInspector = class {
  static {
    __name(this, "CryoFrameInspector");
  }
  static Inspect(message, encoding = "utf8") {
    const sid = CryoFrameFormatter.GetSid(message);
    const ack = CryoFrameFormatter.GetAck(message);
    const type = CryoFrameFormatter.GetType(message);
    const type_str = typeToStringMap[type] || "unknown";
    const payload = CryoFrameFormatter.GetPayload(message, encoding);
    return `[${sid},${ack},${type_str},[${payload}]]`;
  }
};

// node_modules/cryo-server/dist/lib/Common/AckTracker/AckTracker.js
var AckTracker = class {
  static {
    __name(this, "AckTracker");
  }
  MAX_STATE_DURATION_MS;
  log;
  pending = /* @__PURE__ */ new Map();
  ewma_rtt = null;
  alpha = 0.2;
  constructor(MAX_STATE_DURATION_MS = 2500, log2 = CreateDebugLogger("CRYO_SERVER_ACK")) {
    this.MAX_STATE_DURATION_MS = MAX_STATE_DURATION_MS;
    this.log = log2;
  }
  Track(ack, message) {
    this.pending.set(ack, message);
  }
  Confirm(ack) {
    const maybe_ack = this.pending.get(ack);
    if (!maybe_ack)
      return null;
    const rtt = Date.now() - maybe_ack.timestamp;
    if (!this.ewma_rtt)
      this.ewma_rtt = rtt;
    else
      this.ewma_rtt = (1 - this.alpha) * this.ewma_rtt + this.alpha * rtt;
    this.log(`ACK ${ack} confirmed in ${Date.now() - maybe_ack.timestamp} ms`);
    this.pending.delete(ack);
    return maybe_ack;
  }
  /*
      public Has(ack: number): boolean {
          return this.pending.has(ack);
      }
  */
  Sweep() {
    const now = Date.now();
    this.log("Doing housekeeping...");
    let purged = 0;
    for (const [ack, pending] of this.pending.entries()) {
      if (now - pending.timestamp >= this.MAX_STATE_DURATION_MS) {
        this.pending.delete(ack);
        this.log(`Purged message ${CryoFrameInspector.Inspect(pending.message)} (ACK ${ack}) due to being stale for longer than ${this.MAX_STATE_DURATION_MS} milliseconds!`);
        purged++;
      }
    }
    return purged;
  }
  get rtt() {
    return this.ewma_rtt || -1;
  }
  Destroy() {
    this.pending.clear();
  }
};

// node_modules/cryo-server/dist/lib/CryoExtension/CryoExtensionRegistry.js
var log = CreateDebugLogger("CRYO_EXTENSION");
var CryoExtensionExecutor = class {
  static {
    __name(this, "CryoExtensionExecutor");
  }
  session;
  constructor(session) {
    this.session = session;
  }
  async execute_if_present(extension, handler_name, message) {
    if (!extension[handler_name])
      return { should_emit: true };
    log(`${extension.name}::${handler_name} is present. Executing with: `, message.value);
    return new Promise((resolve) => {
      extension[handler_name](this.session, message).then((should_emit) => {
        return { should_emit };
      }).catch((ex) => {
        log(`Call to '${handler_name}' of extension '${extension.name}' threw an error`, ex);
        resolve({ should_emit: true, error: ex });
      });
    });
  }
  async apply_before_send(message) {
    let before_send_result = { should_emit: true };
    log(`Running before_send handler, message: `, message);
    for (const extension of CryoExtensionRegistry.extensions) {
      if (typeof message.value === "string") {
        before_send_result = await this.execute_if_present(extension, "before_send_utf8", message);
      } else {
        before_send_result = await this.execute_if_present(extension, "before_send_binary", message);
      }
    }
    log("after before_send handler, before_send_result:", before_send_result);
    return before_send_result;
  }
  async apply_after_receive(message) {
    let after_receive_result = { should_emit: true };
    log(`Running after_receive handler, message: `, message);
    for (const extension of CryoExtensionRegistry.extensions) {
      if (typeof message.value === "string") {
        after_receive_result = await this.execute_if_present(extension, "on_receive_utf8", message);
      } else {
        after_receive_result = await this.execute_if_present(extension, "on_receive_binary", message);
      }
    }
    log("after after_receive handler, after_receive_result:", after_receive_result);
    return after_receive_result;
  }
};
var CryoExtensionRegistry = class _CryoExtensionRegistry {
  static {
    __name(this, "CryoExtensionRegistry");
  }
  static extensions = [];
  static get_executor(session) {
    return new CryoExtensionExecutor(session);
  }
  static register(extension) {
    const maybe_index = this.extensions.findIndex((existing_extension) => existing_extension.name === extension.name);
    if (maybe_index >= 0)
      throw new Error(`Extension '${extension.name}' is already registered!`);
    this.extensions.push(extension);
  }
  static unregister(extension) {
    const extension_name = typeof extension === "string" ? extension : extension.name;
    const maybe_index = this.extensions.findIndex((extension2) => extension2.name === extension_name);
    if (maybe_index < 0)
      return;
    log(`Unregisted extension '${this.extensions[maybe_index].name}'`);
    this.extensions.splice(maybe_index, 1);
  }
  static Destroy() {
    for (const extension of _CryoExtensionRegistry.extensions) {
      this.unregister(extension);
    }
  }
};

// node_modules/cryo-server/dist/lib/Common/BackpressureManager/BackpressureManager.js
import { clearInterval } from "node:timers";
var BackpressureManager = class {
  static {
    __name(this, "BackpressureManager");
  }
  ws;
  WM_HI;
  WM_LO;
  MAX_Q_BYTES;
  MAX_Q_COUNT;
  drop;
  log;
  on_drop;
  queue = [];
  queued_bytes = 0;
  tick = null;
  stat_log_tick = setInterval(() => this.log_stats(), 5e3);
  constructor(ws, WM_HI, WM_LO, MAX_Q_BYTES, MAX_Q_COUNT, drop, log2, on_drop) {
    this.ws = ws;
    this.WM_HI = WM_HI;
    this.WM_LO = WM_LO;
    this.MAX_Q_BYTES = MAX_Q_BYTES;
    this.MAX_Q_COUNT = MAX_Q_COUNT;
    this.drop = drop;
    this.log = log2;
    this.on_drop = on_drop;
    Guard.CastAs(this.ws);
    if (this.ws?._socket) {
      Guard.CastAssert(this.ws._socket, this.ws?._socket !== void 0, "ws._socket was undefined!");
      this.ws?._socket?.on?.("drain", () => this.try_flush());
    }
    this.tick = setInterval(() => this.try_flush(), 50);
  }
  log_stats() {
    this.log(`Max queue elements: ${this.MAX_Q_COUNT}, Max queued bytes: ${this.MAX_Q_BYTES}, Drop policy: '${this.drop}'`);
    this.log(`Queue length: ${this.queue.length}, Queued bytes: ${this.queued_bytes}, Current buffered bytes: ${this.ws.bufferedAmount}`);
  }
  can_send() {
    Guard.CastAs(this.ws);
    return this.ws.readyState === this.ws.OPEN && this.ws.bufferedAmount < this.WM_HI && this.ws._socket.writable;
  }
  enqueue(buffer, priority = "control", key) {
    if (priority === "control" && this.can_send()) {
      this.ws.send(buffer, { binary: true });
      return true;
    }
    if (this.drop === "dedupe-latest" && key) {
      for (let i = this.queue.length - 1; i >= 0; i--) {
        const item = this.queue[i];
        if (item.key === key) {
          this.queued_bytes -= item.buffer.byteLength;
          this.queue.splice(i, 1);
          break;
        }
      }
    }
    const enqueueWouldExceedMaxQueues = this.queue.length + 1 > this.MAX_Q_COUNT;
    const wouldExceedQueuedBytes = this.queued_bytes + buffer.byteLength > this.MAX_Q_BYTES;
    if (wouldExceedQueuedBytes || enqueueWouldExceedMaxQueues) {
      if (this.drop === "drop-newest")
        return false;
      if (this.drop === "drop-oldest") {
        if (this.queue.length > 0) {
          const evicted_item = this.queue.shift();
          Guard.CastAssert(evicted_item, evicted_item !== void 0, "evicted_item was undefined!");
          this.queued_bytes -= evicted_item.buffer.byteLength;
          this.on_drop?.(evicted_item);
        } else {
          return false;
        }
      }
    }
    if (this.drop === "dedupe-latest") {
      const areWeStillExceeding = this.queue.length + 1 > this.MAX_Q_COUNT || this.queued_bytes + buffer.byteLength > this.MAX_Q_BYTES;
      if (areWeStillExceeding)
        return false;
    }
    this.queue.push({ buffer, priority, key, ts: Date.now() });
    this.queued_bytes += buffer.byteLength;
    this.log_stats();
    this.try_flush();
    return true;
  }
  try_flush() {
    if (!this.can_send())
      return;
    if (this.queue.length > 1)
      this.queue.sort((iA, iB) => iA.priority === iB.priority ? 0 : iA.priority === "control" ? -1 : 1);
    while (this.queue.length > 0 && this.ws.bufferedAmount < this.WM_HI) {
      const item = this.queue.shift();
      Guard.CastAssert(item, item !== void 0, "evicted_item was undefined!");
      this.queued_bytes -= item.buffer.byteLength;
      this.ws.send(item.buffer, { binary: true });
      if (this.ws.bufferedAmount >= this.WM_HI)
        break;
    }
  }
  Destroy() {
    if (this.tick)
      clearInterval(this.tick);
    if (this.stat_log_tick)
      clearInterval(this.stat_log_tick);
    this.stat_log_tick = null;
    this.tick = null;
    this.queue.length = 0;
    this.queued_bytes = 0;
  }
};

// node_modules/cryo-server/dist/lib/CryoServerWebsocketSession/CryoCryptoBox.js
import { createCipheriv, createDecipheriv } from "node:crypto";
var CryoCryptoBox = class {
  static {
    __name(this, "CryoCryptoBox");
  }
  encrypt_key;
  decryption_key;
  nonce = 0;
  constructor(encrypt_key, decryption_key) {
    this.encrypt_key = encrypt_key;
    this.decryption_key = decryption_key;
  }
  create_iv() {
    const iv = Buffer.alloc(12);
    iv.writeUInt32BE(this.nonce++, 8);
    return iv;
  }
  encrypt(plain) {
    const iv = this.create_iv();
    const cipher = createCipheriv("aes-128-gcm", this.encrypt_key, iv);
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }
  decrypt(cipher) {
    const iv = cipher.subarray(0, 12);
    const tag = cipher.subarray(cipher.byteLength - 16);
    const data = cipher.subarray(12, cipher.byteLength - 16);
    const decipher = createDecipheriv("aes-128-gcm", this.decryption_key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }
};

// node_modules/cryo-server/dist/lib/CryoServerWebsocketSession/CryoHandshakeEngine.js
import { createECDH, createHash } from "node:crypto";
var HandshakeState;
(function(HandshakeState2) {
  HandshakeState2[HandshakeState2["INITIAL"] = 0] = "INITIAL";
  HandshakeState2[HandshakeState2["WAIT_CLIENT_HELLO"] = 1] = "WAIT_CLIENT_HELLO";
  HandshakeState2[HandshakeState2["WAIT_CLIENT_DONE"] = 2] = "WAIT_CLIENT_DONE";
  HandshakeState2[HandshakeState2["SECURE"] = 3] = "SECURE";
})(HandshakeState || (HandshakeState = {}));
var CryoHandshakeEngine = class {
  static {
    __name(this, "CryoHandshakeEngine");
  }
  sid;
  send_plain;
  formatter;
  next_ack;
  events;
  ECDH_CURVE_NAME = "prime256v1";
  handshake_state = HandshakeState.INITIAL;
  ecdh = createECDH(this.ECDH_CURVE_NAME);
  transmit_key = null;
  receive_key = null;
  constructor(sid, send_plain, formatter, next_ack, events) {
    this.sid = sid;
    this.send_plain = send_plain;
    this.formatter = formatter;
    this.next_ack = next_ack;
    this.events = events;
    this.ecdh.generateKeys();
  }
  async start_server_hello() {
    if (this.handshake_state !== HandshakeState.INITIAL)
      return;
    const my_pub_key = this.ecdh.getPublicKey(null, "uncompressed");
    const ack = this.next_ack();
    const hello_frame = this.formatter.GetFormatter("server_hello").Serialize(this.sid, ack, my_pub_key);
    await this.send_plain(hello_frame);
    this.handshake_state = HandshakeState.WAIT_CLIENT_HELLO;
  }
  async on_client_hello(frame) {
    if (this.handshake_state !== HandshakeState.WAIT_CLIENT_HELLO) {
      this.events.onFailure(`CLIENT_HELLO received while in state ${this.state}`);
      return;
    }
    const decoded = CryoFrameFormatter.GetFormatter("client_hello").Deserialize(frame);
    const client_pub_key = decoded.payload;
    const secret = this.ecdh.computeSecret(client_pub_key);
    const hash = createHash("sha256").update(secret).digest();
    this.transmit_key = hash.subarray(0, 16);
    this.receive_key = hash.subarray(16, 32);
    this.handshake_state = HandshakeState.WAIT_CLIENT_DONE;
    const done = CryoFrameFormatter.GetFormatter("handshake_done").Serialize(this.sid, decoded.ack, null);
    await this.send_plain(done);
  }
  on_client_handshake_done(_frame) {
    if (this.handshake_state !== HandshakeState.WAIT_CLIENT_DONE) {
      this.events.onFailure(`HANDSHAKE_DONE received while in state ${this.state}`);
      return;
    }
    this.events.onSecure({ receive_key: this.receive_key, transmit_key: this.transmit_key });
    this.handshake_state = HandshakeState.SECURE;
  }
  get is_secure() {
    return this.handshake_state === HandshakeState.SECURE;
  }
  get state() {
    return this.handshake_state;
  }
};

// node_modules/cryo-server/dist/lib/CryoServerWebsocketSession/CryoFrameRouter.js
var CryoFrameRouter = class {
  static {
    __name(this, "CryoFrameRouter");
  }
  is_secure;
  decrypt;
  handlers;
  log;
  constructor(is_secure, decrypt, handlers, log2 = CreateDebugLogger("CRYO_FRAME_ROUTER")) {
    this.is_secure = is_secure;
    this.decrypt = decrypt;
    this.handlers = handlers;
    this.log = log2;
  }
  try_get_type(buf) {
    if (!buf || buf.length < 21)
      return null;
    const type_byte = buf.readUint8(20);
    return type_byte <= BinaryMessageType.HANDSHAKE_DONE ? type_byte : null;
  }
  async do_route(raw) {
    let frame = raw;
    let type;
    type = this.try_get_type(raw);
    if (type === null && this.is_secure()) {
      try {
        frame = this.decrypt(raw);
        type = this.try_get_type(frame);
      } catch (e) {
        this.log(`Decryption failed: ${e}`, raw);
        return;
      }
    }
    if (type === null) {
      this.log(`Unknown frame type`, raw);
      return;
    }
    switch (type) {
      case BinaryMessageType.PING_PONG:
        await this.handlers.on_ping_pong(frame);
        return;
      case BinaryMessageType.ERROR:
        await this.handlers.on_error(frame);
        return;
      case BinaryMessageType.ACK:
        await this.handlers.on_ack(frame);
        return;
      case BinaryMessageType.UTF8DATA:
        await this.handlers.on_utf8(frame);
        return;
      case BinaryMessageType.BINARYDATA:
        await this.handlers.on_binary(frame);
        return;
      case BinaryMessageType.SERVER_HELLO:
        await this.handlers.on_server_hello?.(frame);
        return;
      case BinaryMessageType.CLIENT_HELLO:
        await this.handlers.on_client_hello?.(frame);
        return;
      case BinaryMessageType.HANDSHAKE_DONE:
        await this.handlers.on_handshake_done(frame);
        return;
      default:
        this.log(`Unsupported binary message type ${type}!`);
    }
  }
};

// node_modules/cryo-server/dist/lib/CryoServerWebsocketSession/CryoServerWebsocketSession.js
var CloseCode;
(function(CloseCode2) {
  CloseCode2[CloseCode2["CLOSE_GRACEFUL"] = 4e3] = "CLOSE_GRACEFUL";
  CloseCode2[CloseCode2["CLOSE_CLIENT_ERROR"] = 4001] = "CLOSE_CLIENT_ERROR";
  CloseCode2[CloseCode2["CLOSE_SERVER_ERROR"] = 4002] = "CLOSE_SERVER_ERROR";
  CloseCode2[CloseCode2["CLOSE_CALE_MISMATCH"] = 4010] = "CLOSE_CALE_MISMATCH";
  CloseCode2[CloseCode2["CLOSE_CALE_HANDSHAKE"] = 4011] = "CLOSE_CALE_HANDSHAKE";
})(CloseCode || (CloseCode = {}));
var CryoServerWebsocketSession = class extends EventEmitter {
  static {
    __name(this, "CryoServerWebsocketSession");
  }
  remoteClient;
  remoteSocket;
  remoteName;
  use_cale;
  client_ack_tracker = new AckTracker();
  bp_mgr = null;
  current_ack = 0;
  bytes_rx = 0;
  bytes_tx = 0;
  destroyed = false;
  log;
  ping_pong_formatter = CryoFrameFormatter.GetFormatter("ping_pong");
  ack_formatter = CryoFrameFormatter.GetFormatter("ack");
  error_formatter = CryoFrameFormatter.GetFormatter("error");
  utf8_formatter = CryoFrameFormatter.GetFormatter("utf8data");
  binary_formatter = CryoFrameFormatter.GetFormatter("binarydata");
  crypto = null;
  handshake;
  router;
  storage = {};
  constructor(remoteClient, remoteSocket, remoteName, backpressure_opts, use_cale) {
    super();
    this.remoteClient = remoteClient;
    this.remoteSocket = remoteSocket;
    this.remoteName = remoteName;
    this.use_cale = use_cale;
    this.log = CreateDebugLogger(`CRYO_SERVER_SESSION`);
    this.bp_mgr = new BackpressureManager(remoteClient, backpressure_opts.highWaterMark, backpressure_opts.lowWaterMark, backpressure_opts.maxQueuedBytes, backpressure_opts.maxQueueCount, backpressure_opts.dropPolicy, CreateDebugLogger(`CRYO_BACKPRESSURE`));
    const handshake_events = {
      onSecure: /* @__PURE__ */ __name(({ transmit_key, receive_key }) => {
        this.crypto = new CryoCryptoBox(transmit_key, receive_key);
        this.log("Handshake completed. Session is now secured.");
      }, "onSecure"),
      onFailure: /* @__PURE__ */ __name((reason) => {
        this.log(`Handshake failure: ${reason}`);
        this.Destroy(CloseCode.CLOSE_CALE_HANDSHAKE, "Error during CALE handshake.");
      }, "onFailure")
    };
    this.handshake = new CryoHandshakeEngine(this.Client.sessionId, (buffer) => this.Send(buffer, true), CryoFrameFormatter, () => this.inc_get_ack(), handshake_events);
    this.router = new CryoFrameRouter(() => this.use_cale && this.handshake.is_secure, (buffer) => this.crypto.decrypt(buffer), {
      on_ping_pong: /* @__PURE__ */ __name(async (b) => this.HandlePingPongMessage(b), "on_ping_pong"),
      on_ack: /* @__PURE__ */ __name(async (b) => this.HandleAckMessage(b), "on_ack"),
      on_error: /* @__PURE__ */ __name(async (b) => this.HandleErrorMessage(b), "on_error"),
      on_utf8: /* @__PURE__ */ __name(async (b) => this.HandleUTF8DataMessage(b), "on_utf8"),
      on_binary: /* @__PURE__ */ __name(async (b) => this.HandleBinaryDataMessage(b), "on_binary"),
      on_client_hello: /* @__PURE__ */ __name(async (b) => {
        if (use_cale)
          await this.handshake.on_client_hello(b);
        else
          this.Destroy(CloseCode.CLOSE_CALE_MISMATCH, "CALE Mismatch. The client excepts CALE encryption, which is currently disabled.");
      }, "on_client_hello"),
      on_handshake_done: /* @__PURE__ */ __name(async (b) => this.handshake.on_client_handshake_done(b), "on_handshake_done")
    });
    remoteSocket.once("end", this.TCPSOCKET_HandleRemoteEnd.bind(this));
    remoteSocket.once("error", this.TCPSOCKET_HandleRemoteError.bind(this));
    remoteClient.on("close", this.WEBSOCKET_HandleRemoteClose.bind(this));
    remoteClient.on("message", (raw) => this.router.do_route(raw));
    if (use_cale)
      this.handshake.start_server_hello().then(() => null);
    else
      this.log("CALE disabled, running in unencrypted mode.");
  }
  inc_get_ack() {
    if (this.current_ack + 1 > 2 ** 32 - 1)
      this.current_ack = 0;
    return this.current_ack++;
  }
  /*
  * Sends a PING frame to the client
  * */
  async Ping() {
    const new_ack_id = this.inc_get_ack();
    const encodedPingMessage = this.ping_pong_formatter.Serialize(this.Client.sessionId, new_ack_id, "ping");
    await this.Send(encodedPingMessage);
  }
  /*
  * Send an UTF8 string to the client
  * */
  //noinspection JSUnusedGlobalSymbols
  async SendUTF8(message) {
    const new_ack_id = this.inc_get_ack();
    const boxed_message = { value: message };
    const result = await CryoExtensionRegistry.get_executor(this).apply_before_send(boxed_message);
    if (!result.should_emit)
      return;
    const encodedUtf8DataMessage = this.utf8_formatter.Serialize(this.Client.sessionId, new_ack_id, boxed_message.value);
    this.client_ack_tracker.Track(new_ack_id, {
      message: encodedUtf8DataMessage,
      timestamp: Date.now(),
      payload: boxed_message.value
    });
    await this.Send(encodedUtf8DataMessage);
  }
  /*
  * Send a binary message to the client
  * */
  //noinspection JSUnusedGlobalSymbols
  async SendBinary(message) {
    const new_ack_id = this.inc_get_ack();
    const boxed_message = { value: message };
    const result = await CryoExtensionRegistry.get_executor(this).apply_before_send(boxed_message);
    if (!result.should_emit)
      return;
    const encodedBinaryDataMessage = this.binary_formatter.Serialize(this.Client.sessionId, new_ack_id, boxed_message.value);
    this.client_ack_tracker.Track(new_ack_id, {
      message: encodedBinaryDataMessage,
      timestamp: Date.now(),
      payload: boxed_message.value
    });
    await this.Send(encodedBinaryDataMessage);
  }
  /*
  * Respond to PONG frames and set the client to be alive
  * */
  async HandlePingPongMessage(message) {
    const decodedPingPongMessage = this.ping_pong_formatter.Deserialize(message);
    if (decodedPingPongMessage.payload !== "pong")
      return;
    this.Client.isAlive = true;
  }
  /*
  * Handling of binary error messages from the client, currently just log it
  * */
  async HandleErrorMessage(message) {
    const decodedErrorMessage = this.error_formatter.Deserialize(message);
    this.log(decodedErrorMessage.payload);
  }
  /*
  * Handle ACK messages from the client
  * */
  async HandleAckMessage(message) {
    const decodedAckMessage = this.ack_formatter.Deserialize(message);
    const ack_id = decodedAckMessage.ack;
    const found_message = this.client_ack_tracker.Confirm(ack_id);
    if (!found_message) {
      this.log(`Received ACK ${ack_id} for unknown message!`);
      return;
    }
    this.log(`Acknowledging client message ${ack_id} !`);
  }
  /*
  * Handle DATA messages from the client
  * */
  async HandleUTF8DataMessage(message) {
    const decodedDataMessage = this.utf8_formatter.Deserialize(message);
    const ack_id = decodedDataMessage.ack;
    const encodedACKMessage = this.ack_formatter.Serialize(this.Client.sessionId, ack_id);
    await this.Send(encodedACKMessage);
    const boxed_message = { value: decodedDataMessage.payload };
    const result = await CryoExtensionRegistry.get_executor(this).apply_after_receive(boxed_message);
    if (result.should_emit)
      this.emit("message-utf8", boxed_message.value);
  }
  /*
  * Handle DATA messages from the client
  * */
  async HandleBinaryDataMessage(message) {
    const decodedDataMessage = this.binary_formatter.Deserialize(message);
    const ack_id = decodedDataMessage.ack;
    const encodedACKMessage = this.ack_formatter.Serialize(this.Client.sessionId, ack_id);
    await this.Send(encodedACKMessage);
    const boxed_message = { value: decodedDataMessage.payload };
    const result = await CryoExtensionRegistry.get_executor(this).apply_after_receive(boxed_message);
    if (result.should_emit)
      this.emit("message-binary", boxed_message.value);
  }
  TranslateCloseCode(code) {
    switch (code) {
      case CloseCode.CLOSE_GRACEFUL:
        return "Connection closed normally.";
      case CloseCode.CLOSE_CLIENT_ERROR:
        return "Connection closed due to a client error.";
      case CloseCode.CLOSE_SERVER_ERROR:
        return "Connection closed due to a server error.";
      case CloseCode.CLOSE_CALE_MISMATCH:
        return "Connection closed due to a mismatch in client/server CALE configuration.";
      case CloseCode.CLOSE_CALE_HANDSHAKE:
        return "Connection closed due to an error in the CALE handshake.";
      default:
        return "Unspecified cause for connection closure.";
    }
  }
  WEBSOCKET_HandleRemoteClose(code, reason) {
    const code_string = this.TranslateCloseCode(code);
    this.log(`Client ${this.remoteName} has disconnected. Code=${code_string}, reason=${reason.toString("utf8")}`);
    this.Destroy(CloseCode.CLOSE_GRACEFUL, "Connection closed gracefully.");
  }
  /*
  * Log hangup and destroy session
  * */
  TCPSOCKET_HandleRemoteEnd() {
    this.log(`TCP Peer '${this.remoteName}' connection closed cleanly by client session.`);
    this.Destroy(CloseCode.CLOSE_GRACEFUL, "Connection closed gracefully.");
  }
  /*
  * Log error and destroy session
  * */
  TCPSOCKET_HandleRemoteError(err) {
    this.log(`TCP Peer '${this.remoteName}' threw an error '${err.message}' (${err?.code})`);
    this.Destroy(CloseCode.CLOSE_CLIENT_ERROR, "Connection closed erroneously.");
  }
  /*
  * Send a buffer to the client
  * */
  async Send(encodedMessage, plain = false) {
    const type = CryoFrameFormatter.GetType(encodedMessage);
    const prio = type === BinaryMessageType.ACK || type === BinaryMessageType.PING_PONG || type === BinaryMessageType.ERROR ? "control" : "data";
    let outgoing = encodedMessage;
    if (this.use_cale && this.secure && !plain)
      outgoing = this.crypto.encrypt(encodedMessage);
    const ok = this.bp_mgr.enqueue(outgoing, prio);
    if (!ok) {
      this.log(`Frame ${CryoFrameFormatter.GetAck(encodedMessage)} was dropped by policy.`);
      return;
    }
    this.bytes_tx += outgoing.byteLength;
  }
  get Client() {
    return this.remoteClient;
  }
  get_ack_tracker() {
    return this.client_ack_tracker;
  }
  get rx() {
    return this.bytes_rx;
  }
  get tx() {
    return this.bytes_tx;
  }
  get id() {
    return this.Client.sessionId;
  }
  get secure() {
    return this.use_cale && this.handshake?.state === HandshakeState.SECURE && this.crypto !== null;
  }
  Destroy(code = 4e3, message = "Closing session.") {
    this.bp_mgr?.Destroy();
    this.client_ack_tracker.Destroy();
    try {
      this.log(`Teardown of session. Code=${code}, reason=${message}`);
      this.Client.close(code, message);
    } catch {
    }
    if (!this.destroyed)
      this.emit("closed");
    this.destroyed = true;
  }
  Set(key, value) {
    this.storage[key] = value;
  }
  Get(key) {
    return this.storage[key];
  }
};

// node_modules/cryo-server/dist/lib/Common/Util/OverwriteUnset.js
function OverwriteUnset(target, source) {
  for (const s_key in source) {
    const key = s_key;
    if (target[key] == null) {
      target[key] = source[key];
    }
  }
  return target;
}
__name(OverwriteUnset, "OverwriteUnset");

// node_modules/cryo-server/dist/lib/CryoWebsocketServer/CryoWebsocketServer.js
var CryoWebsocketServer = class _CryoWebsocketServer extends EventEmitter2 {
  static {
    __name(this, "CryoWebsocketServer");
  }
  server;
  tokenValidator;
  backpressure_options;
  use_cale;
  ws_server;
  WebsocketHeartbeatInterval;
  sessions = [];
  log;
  static async Create(pTokenValidator, options) {
    const keepAliveInterval = options?.keepAliveIntervalMs ?? 15e3;
    const sockPort = options?.port ?? 8080;
    const use_cale = options?.use_cale ?? true;
    const backpressure = options?.backpressure ?? {};
    const server2 = options?.ssl && options.ssl.key && options.ssl.cert ? https.createServer(options.ssl) : http.createServer();
    const bpres_opts_filled = OverwriteUnset(backpressure, {
      dropPolicy: "drop-oldest",
      highWaterMark: 16 * 1024 * 1024,
      lowWaterMark: 1024 * 1024,
      maxQueuedBytes: 8 * 1024 * 1024,
      maxQueueCount: 1024
    });
    return new _CryoWebsocketServer(server2, pTokenValidator, keepAliveInterval, sockPort, bpres_opts_filled, use_cale);
  }
  constructor(server2, tokenValidator, keepAliveInterval, socketPort, backpressure_options, use_cale = true) {
    super();
    this.server = server2;
    this.tokenValidator = tokenValidator;
    this.backpressure_options = backpressure_options;
    this.use_cale = use_cale;
    this.log = CreateDebugLogger("CRYO_SERVER");
    this.ws_server = new WebSocketServer({ noServer: true });
    this.WebsocketHeartbeatInterval = setInterval2(this.Heartbeat.bind(this), keepAliveInterval).ref();
    this.server.on("upgrade", this.HTTPUpgradeCallback.bind(this));
    this.server.listen(socketPort, () => {
      this.log(`SSL support? ${this.server instanceof https.Server}`);
      this.emit("listening");
    });
  }
  __denyAndDestroy(pSocket, message) {
    const body = `<html lang="de-DE"><body><h1>401 Unauthorized</h1><p>${message}</p></body></html>`;
    const response = `HTTP/1.1 401 Unauthorized\r
Content-Type: text/html; charset=utf-8\r
Content-Length: ${Buffer.byteLength(body)}\r
Connection: close\r
\r
` + body;
    pSocket.write(response, () => {
      pSocket.end(() => {
        this.log(message);
      });
    });
  }
  async HTTPUpgradeCallback(request, socket, head) {
    const socketFmt = `${request.socket.remoteAddress}:${request.socket.remotePort}`;
    this.log(`Upgrade request from ${socketFmt} ...`);
    const full_host_url = new URL(`ws://${process.env.HOST ?? "localhost"}${request.url}`);
    const authorization = full_host_url.searchParams.get("authorization");
    const x_cryo_sid = full_host_url.searchParams.get("x-cryo-sid");
    if (!authorization) {
      this.__denyAndDestroy(socket, `Upgrade request for ${socketFmt} was refused. No auth data supplied.`);
      return;
    }
    if (!authorization.startsWith("Bearer")) {
      this.__denyAndDestroy(socket, `Upgrade request for ${socketFmt} was refused. No auth data supplied.`);
      return;
    }
    if (!x_cryo_sid) {
      this.__denyAndDestroy(socket, `Upgrade request for ${socketFmt} was refused. No SID supplied.`);
      return;
    }
    if (this.sessions.findIndex((s) => s.id === x_cryo_sid) > -1) {
      this.__denyAndDestroy(socket, `Upgrade request for ${socketFmt} was refused. The session already exists.`);
      return;
    }
    const clientSessionId = `${x_cryo_sid}`;
    const clientBearerToken = authorization.slice(7);
    const isTokenValid = await this.tokenValidator.validate(clientBearerToken);
    if (!isTokenValid) {
      this.__denyAndDestroy(socket, `Upgrade request for ${socketFmt} was refused. Invalid bearer token in authorization query.`);
      return;
    }
    this.log(`Upgrade request from ${socketFmt} was accepted.`);
    this.ws_server.handleUpgrade(request, socket, head, (client, request2) => {
      this.log(`Internal WS server completed upgrade for ${socketFmt}.`);
      this.WSUpgradeCallback(request2, socket, client, clientSessionId, clientBearerToken);
    });
  }
  async WSUpgradeCallback(request, socket, client, clientSid, clientBearerToken) {
    Guard.CastAs(client);
    const socketFmt = `${request.socket.remoteAddress}:${request.socket.remotePort}`;
    client.isAlive = true;
    client.sessionId = clientSid;
    const session = new CryoServerWebsocketSession(client, socket, socketFmt, this.backpressure_options, this.use_cale);
    session.Set("__TOKEN", clientBearerToken);
    this.sessions.push(session);
    session.on("closed", () => {
      const s_idx = this.sessions.findIndex((s) => s.id === session.id);
      this.sessions.splice(s_idx, 1);
    });
    this.emit("session", session);
  }
  /*
  * Take care of pinging the clients, removing them if they are not responding anymore and doing per session stat & housekeeping
  * */
  async Heartbeat() {
    for (const session of this.sessions) {
      if (!session.Client.isAlive) {
        this.log(`Terminating dead client session ${session.Client.sessionId}`);
        const sIdx = this.sessions.findIndex((s) => s.Client.sessionId === session.Client.sessionId);
        const retrievedSession = this.sessions.splice(sIdx, 1)[0];
        retrievedSession.Destroy(4001, "Disconnecting session due to not responding to ping frames.");
        continue;
      }
      const session_tracker = session.get_ack_tracker();
      session.emit("stat-ack-timeout", session_tracker.Sweep());
      session.emit("stat-rtt", session_tracker.rtt);
      session.emit("stat-bytes-tx", session.tx);
      session.emit("stat-bytes-rx", session.rx);
      session.Client.isAlive = false;
      await session.Ping();
    }
  }
  /**
   * Teardown all sessions, all connections, timers and extensions
   */
  //noinspection JSUnusedGlobalSymbols
  Destroy() {
    CryoExtensionRegistry.Destroy();
    this.server.removeAllListeners();
    this.server.close();
    this.WebsocketHeartbeatInterval.unref();
    clearInterval2(this.WebsocketHeartbeatInterval);
    for (const session of this.sessions)
      session.Destroy(4e3, "Server shutdown.");
    this.ws_server.removeAllListeners();
    this.ws_server.close();
  }
  /**
   * Register a server-side cryo extension
   */
  //noinspection JSUnusedGlobalSymbols
  RegisterExtension(extension) {
    CryoExtensionRegistry.register(extension);
  }
};

// node_modules/cryo-server/dist/lib/index.js
async function cryo(pTokenValidator, options) {
  return CryoWebsocketServer.Create(pTokenValidator, options);
}
__name(cryo, "cryo");

// src/core/ComponentTree.ts
var ComponentTree = class _ComponentTree {
  constructor(root) {
    this.root = root;
    root.onMounted?.();
  }
  static {
    __name(this, "ComponentTree");
  }
  static repaintQueue = [];
  findById(id, current = this.root) {
    return current.findById(id);
  }
  dispatchEvent(event) {
    const target = this.findById(event.target);
    if (!target) {
      console.warn(`Target '${event.target}' could not be found!`);
      return;
    }
    if (!target?.handleEvent) {
      console.warn(`Target '${event.target}' cannot handle events!`);
      return;
    }
    target.handleEvent(event);
  }
  async renderFull() {
    return this.root.renderRecursive();
  }
  async renderById(id) {
    const target = this.findById(id);
    if (!target)
      throw new Error(`Target '${id}' could not be found!`);
    if (!target?.renderRecursive()) {
      console.warn(`Target '${target}' can not be rendered.`);
      return null;
    }
    return target.renderRecursive();
  }
  findParentOf(id, current = this.root) {
    for (const child of current.children) {
      if (child.id === id)
        return current;
      const found = this.findParentOf(id, child);
      if (found)
        return found;
    }
    return null;
  }
  replaceComponent(id, replacee) {
    const parent = this.findParentOf(id);
    if (!parent)
      throw new Error(`Parent component of component '${id}' could not be found!`);
    parent.removeChild(id);
    parent.addChild(replacee);
    replacee.parent = parent;
    replacee.onMounted?.();
  }
  async getUpdatedComponents() {
    const components = [];
    while (_ComponentTree.repaintQueue.length > 0) {
      const toUpdate = _ComponentTree.repaintQueue.pop();
      components.push({ target: toUpdate.id, html: await toUpdate.renderRecursive() });
    }
    return components;
  }
};

// src/UI/Base/BaseComponent/BaseComponent.ts
import { randomUUID } from "node:crypto";

// src/UI/Base/BaseComponent/BaseComponent.module.css
var BaseComponent = "BaseComponent_BaseComponent";

// src/UI/Base/BaseComponent/BaseComponent.ts
var UUIDPool = class _UUIDPool {
  static {
    __name(this, "UUIDPool");
  }
  static _instance = void 0;
  uuids = /* @__PURE__ */ new Set();
  get() {
    const newUUID = randomUUID();
    if (this.uuids.has(newUUID))
      return this.get();
    this.uuids.add(newUUID);
    return newUUID;
  }
  static get Instance() {
    if (!_UUIDPool._instance)
      _UUIDPool._instance = new _UUIDPool();
    return _UUIDPool._instance;
  }
};
var BaseComponent2 = class {
  constructor(id, className, styleOverrides) {
    this.className = className;
    this.styleOverrides = styleOverrides;
    this.id = `${id}-${UUIDPool.Instance.get()}`;
  }
  static {
    __name(this, "BaseComponent");
  }
  id;
  parent;
  children = [];
  events = [];
  dirty = false;
  async renderRecursive() {
    if (this.dirty)
      this.dirty = false;
    const rendered = await this.render();
    let computedStyle = "";
    let dataEvent = "";
    if (this.styleOverrides)
      computedStyle = `style="${Object.entries(this.styleOverrides).reduce((sheet, entry) => sheet + `${entry[0]}: ${entry[1]};`, "")}"`;
    if (this.events && this.events.length > 0)
      dataEvent = `data-event="${this.events.join(",")}"`;
    return `
                <div data-target="${this.id}" ${dataEvent}${computedStyle} class="${BaseComponent} ${this.className}">
                    ${rendered}
                </div>`;
  }
  addChild(child) {
    child.parent = this;
    this.children.push(child);
  }
  removeChild(child_id) {
    this.children = this.children.filter((child) => child_id !== child.id);
  }
  findById(id) {
    if (this.id === id)
      return this;
    for (const child of this.children) {
      const found = child.findById(id);
      if (found)
        return found;
    }
    return null;
  }
  repaint() {
    ComponentTree.repaintQueue.push(this);
  }
};

// src/UI/Components/AppComponent/AppComponent.module.css
var AppComponent = "AppComponent_AppComponent";

// src/UI/Components/AppComponent/AppComponent.ts
var AppComponent2 = class extends BaseComponent2 {
  constructor(navBar, mainContent) {
    super("APP", AppComponent);
    this.navBar = navBar;
    this.mainContent = mainContent;
    this.addChild(navBar);
    this.addChild(mainContent);
  }
  static {
    __name(this, "AppComponent");
  }
  async render() {
    const renderedNavigation = await this.navBar.renderRecursive();
    const renderedContent = await this.mainContent.renderRecursive();
    return `${renderedNavigation}${renderedContent}`;
  }
};

// src/UI/Base/BaseLayout/BaseLayout.ts
var BaseLayout = class extends BaseComponent2 {
  static {
    __name(this, "BaseLayout");
  }
  constructor(id, className) {
    super(`LAYOUT_${id}`, `${className}`);
  }
};

// src/UI/Layouts/TwoColumnsLayout/TwoColumnsLayout.module.css
var TwoColumnsLayout = "TwoColumnsLayout_TwoColumnsLayout";

// src/UI/Layouts/TwoColumnsLayout/TwoColumnsLayout.ts
var TwoColumnsLayout2 = class extends BaseLayout {
  constructor(left, right) {
    super("TWO_COLUMNS", TwoColumnsLayout);
    this.left = left;
    this.right = right;
    if (left)
      this.addChild(left);
    if (right)
      this.addChild(right);
  }
  static {
    __name(this, "TwoColumnsLayout");
  }
  setLeft(value) {
    this.left = value;
    this.addChild(this.left);
  }
  setRight(value) {
    this.right = value;
    this.addChild(this.right);
  }
  async render() {
    return [await this.left?.renderRecursive(), await this.right?.renderRecursive()].join("");
  }
  handleEvent(event) {
    this.left?.handleEvent?.(event);
    this.right?.handleEvent?.(event);
  }
};

// src/UI/Layouts/GridLayout/GridLayout.module.css
var GridLayout = "GridLayout_GridLayout";

// src/UI/Layouts/GridLayout/GridLayout.ts
var GridLayout2 = class extends BaseComponent2 {
  static {
    __name(this, "GridLayout");
  }
  constructor(items = []) {
    super("GRID", GridLayout);
    for (const item of items)
      this.addChild(item);
  }
  async render() {
    const renderedChildren = await Promise.all(this.children.map((child) => child.renderRecursive()));
    return renderedChildren.join("");
  }
  handleEvent(event) {
    for (const child of this.children) {
      child.handleEvent?.(event);
    }
  }
};

// src/UI/Components/FrameComponent/FrameComponent.ts
var FrameComponent = class extends BaseComponent2 {
  static {
    __name(this, "FrameComponent");
  }
  constructor(children = []) {
    super("FRAME", "frameComponent");
    for (const child of children)
      this.addChild(child);
  }
  async render() {
    const renderedChildren = await Promise.all(this.children.map((child) => child.renderRecursive()));
    return renderedChildren.join("");
  }
  handleEvent(event) {
    for (const child of this.children) {
      child.handleEvent?.(event);
    }
  }
};

// src/UI/Components/GridItemComponent/GridItemComponent.module.css
var GridItemComponent = "GridItemComponent_GridItemComponent";

// src/UI/Components/GridItemComponent/GridItemComponent.ts
var GridItemComponent2 = class extends BaseComponent2 {
  constructor(item) {
    super("GRID_ITEM", GridItemComponent);
    this.item = item;
    if (item)
      this.addChild(item);
  }
  static {
    __name(this, "GridItemComponent");
  }
  events = ["click"];
  async render() {
    if (this.item)
      return this.item.renderRecursive();
    return "";
  }
  handleEvent(event) {
    switch (event.type) {
      case "click":
        this.item.setContent(`${Math.random()}`);
        break;
      default:
        return;
    }
  }
};

// src/UI/Components/ParagraphComponent/ParagraphComponent.module.css
var ParagraphComponent = "ParagraphComponent_ParagraphComponent";

// src/UI/Components/ParagraphComponent/ParagraphComponent.ts
var ParagraphComponent2 = class extends BaseComponent2 {
  constructor(content) {
    super("PARAGRAPH", ParagraphComponent);
    this.content = content;
  }
  static {
    __name(this, "ParagraphComponent");
  }
  async render() {
    return `<p>${this.content || ""}</p>`;
  }
  setContent(content) {
    this.content = content;
  }
};

// src/UI/Components/NavbarComponent/NavbarComponent.module.css
var NavbarComponent = "NavbarComponent_NavbarComponent";
var tabs = "NavbarComponent_tabs";
var buttons = "NavbarComponent_buttons";

// src/UI/Components/NavbarComponent/NavbarComponent.ts
var NavbarComponent2 = class extends BaseComponent2 {
  constructor(buttons2 = [], tabs2 = []) {
    super("NAVBAR", NavbarComponent);
    this.buttons = buttons2;
    this.tabs = tabs2;
    for (const child of [...this.buttons, ...this.tabs])
      this.addChild(child);
  }
  static {
    __name(this, "NavbarComponent");
  }
  async render() {
    const renderedButtons = await Promise.all(this.buttons.map((button) => button.renderRecursive()));
    const renderedTabs = await Promise.all(this.tabs.map((tab) => tab.renderRecursive()));
    return `
            <div class="${tabs}">${renderedTabs.join("")}</div>
            <div class="${buttons}">${renderedButtons.join("")}</div>
        `;
  }
  addButton(button) {
    this.buttons.push(button);
    this.addChild(button);
  }
  removeButton(target_id) {
    this.buttons = this.buttons.filter((button) => button.id !== target_id);
    this.removeChild(target_id);
  }
  addTab(tab) {
    this.tabs.push(tab);
    this.addChild(tab);
  }
  removeTab(target_id) {
    this.tabs = this.tabs.filter((tab) => tab.id !== target_id);
    this.removeChild(target_id);
  }
  handleEvent(event) {
    for (const child of this.children) {
      child.handleEvent?.(event);
    }
  }
};

// src/UI/Components/HeaderComponent/HeaderComponent.module.css
var HeaderComponent = "HeaderComponent_HeaderComponent";

// src/UI/Components/HeaderComponent/HeaderComponent.ts
var HeaderComponent2 = class extends BaseComponent2 {
  constructor(content = "", size = 1) {
    super("HEADER", HeaderComponent);
    this.content = content;
    this.size = size;
  }
  static {
    __name(this, "HeaderComponent");
  }
  async render() {
    return `<h${this.size}>${this.content}</h${this.size}>`;
  }
  setContent(content) {
    this.content = content;
  }
};

// src/backend.ts
import { inspect } from "node:util";

// src/UI/Components/FormComponent/FormComponent.module.css
var FormComponent = "FormComponent_FormComponent";

// src/UI/Components/FormComponent/FormComponent.ts
var FormComponent2 = class extends BaseComponent2 {
  constructor(inputs) {
    super("FORM", FormComponent);
    this.inputs = inputs;
    for (const input of inputs)
      this.addChild(input);
  }
  static {
    __name(this, "FormComponent");
  }
  events = ["submit"];
  async render() {
    const rendered = await Promise.all(this.children.map((child) => child.renderRecursive()));
    const renderedSubmissiveButton = `<input type="submit" value="Submit"/>`;
    return `<form>${rendered.join("")}${renderedSubmissiveButton}></form>`;
  }
  handleEvent(event) {
    switch (event.type) {
      case "submit":
        let cur = this;
        while (cur?.parent !== void 0) {
          cur = cur?.parent;
        }
        const frame = cur.children.find((child) => child instanceof TwoColumnsLayout2).children.find((child) => child instanceof FrameComponent);
        frame?.addChild(new ParagraphComponent2(`YOUR COCK IS ${event.data.cockSz} UNITS OF MEASUREMENTS BIG.`));
        frame?.repaint();
        break;
      default:
        return;
    }
  }
};

// src/UI/Components/InputComponent/InputComponent.module.css
var InputComponent = "InputComponent_InputComponent";

// src/UI/Components/InputComponent/InputComponent.ts
var InputComponent2 = class extends BaseComponent2 {
  constructor(label, key, type = "text") {
    super("INPUT", InputComponent);
    this.label = label;
    this.key = key;
    this.type = type;
  }
  static {
    __name(this, "InputComponent");
  }
  async render() {
    const input = `<input required id="__${this.id}" step="0.01" name="${this.key}" type="${this.type}" />`;
    const label = `<label for="__${this.id}">${this.label}</label>`;
    return `${label}${input}`;
  }
};

// src/backend.ts
var PORT = 8080;
var Validator = class {
  static {
    __name(this, "Validator");
  }
  async validate(token) {
    return token === "test";
  }
};
var server = await cryo(new Validator(), { use_cale: false, port: PORT, keepAliveIntervalMs: 5e3 });
server.on("session", async (session) => {
  console.log(`New session '${session.id}' connected!`);
  const app = new AppComponent2(
    new NavbarComponent2(
      [
        new ParagraphComponent2("Btn 1"),
        new ParagraphComponent2("Btn 2")
      ],
      [
        new ParagraphComponent2("Tab 1"),
        new ParagraphComponent2("Tab 2")
      ]
    ),
    new TwoColumnsLayout2(
      new GridLayout2(
        [
          new GridItemComponent2(new ParagraphComponent2("Grid Item 1")),
          new GridItemComponent2(new ParagraphComponent2("Grid Item 2")),
          new GridItemComponent2(new ParagraphComponent2("Grid Item 3")),
          new GridItemComponent2(new ParagraphComponent2("Grid Item 4")),
          new GridItemComponent2(new ParagraphComponent2("Grid Item 5")),
          new GridItemComponent2(new ParagraphComponent2("Grid Item 6"))
        ]
      ),
      new FrameComponent([
        new HeaderComponent2("Fantastic fucking header right here!"),
        new ParagraphComponent2(`Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.`),
        new FormComponent2([
          new InputComponent2("Size of cock", "cockSz", "number"),
          new InputComponent2("Your name", "urName", "text"),
          new InputComponent2("Your d.o.b", "urDob", "date")
        ])
      ])
    )
  );
  const tree = new ComponentTree(app);
  await session.SendUTF8(JSON.stringify({ target: "root", html: await tree.renderFull() }));
  session.on("message-utf8", async (message) => {
    const { type, data, target } = JSON.parse(message);
    console.log(`Received UIEvent '${type}' on '${target}' with data '${inspect(data, false, 6, true)}'`);
    tree.dispatchEvent({ target, data, type });
    const html = await tree.renderById(target);
    if (html) {
      console.info(`UIEvent '${type}' on '${target}' => '${target}' was re-rendered!`);
      await session.SendUTF8(JSON.stringify({ target, html }));
    }
    const maybeRepainted = await tree.getUpdatedComponents();
    if (maybeRepainted.length === 0)
      return;
    console.info(`UIEvent '${type}' on '${target}' => '${maybeRepainted.length}' components were re-rendered!`);
    for (const { target: target2, html: html2 } of maybeRepainted) {
      await session.SendUTF8(JSON.stringify({ target: target2, html: html2 }));
    }
  });
  session.on("closed", () => {
    console.log(`Session '${session.id}' closed`);
  });
});
server.on("listening", () => {
  console.log(`CryoUI listening on port ${PORT}`);
});
//# sourceMappingURL=backend.js.map
